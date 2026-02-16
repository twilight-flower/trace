use std::collections::HashSet;
use std::path::{
    Path,
    PathBuf,
};

use trace::{
    ExportOutputFormat,
    RoomWithCachedInfo,
    SessionsFile,
    add_at_to_user_id_if_applicable,
    nonfirst_login,
    user_id_to_crypto_store_path,
};

use argh::FromArgs;
use directories::ProjectDirs;
use futures::StreamExt;
use matrix_sdk::{
    config::SyncSettings,
    encryption::verification::{
        AcceptSettings,
        SasState,
        Verification,
        VerificationRequest,
        VerificationRequestState,
    },
    ruma::{
        events::key::verification::{
            request::ToDeviceKeyVerificationRequestEvent,
            ShortAuthenticationString,
        },
        presence::PresenceState,
        UserId,
    },
    Client,
};
use rpassword::read_password;
use serde::Serialize;

//////////////
//   Args   //
//////////////

#[derive(FromArgs)]
/// Trace Matrix downloader client
struct Args {
    #[argh(subcommand)]
    subcommand: RootSubcommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum RootSubcommand {
    Export(Export),
    ListRooms(ListRooms),
    Session(SessionCommand),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "export")]
/// Export logs from rooms
struct Export {
    #[argh(positional)]
    /// user_id (of the form @alice:example.com) to export rooms accessible to
    user_id: String,
    #[argh(positional)]
    /// space-separated list of room IDs (of the form !abcdefghijklmnopqr:example.com), aliases (of the form #room:example.com), or display names (e.g. 'Example Room') to export
    rooms: Vec<String>,
    #[argh(option, short = 'f')]
    /// format to export to; valid options are 'json' and 'txt'; flag can be used multiple times to export multiple formats in a single run; if flag is unspecified, default output format is json
    formats: Vec<String>,
    #[argh(option, short = 'o')]
    /// path of directory to output files to; if unspecified, defaults to current directory
    output: Option<PathBuf>,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "list-rooms")]
/// List rooms accessible from a given user ID's login
struct ListRooms {
    #[argh(positional)]
    /// user id (of the form @alice:example.com) to list rooms from
    user_id: String,
    #[argh(switch, short = 'j')]
    /// display room list as JSON rather than as human-readable text
    json: bool,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "session")]
/// Add, remove, list, or modify sessions
struct SessionCommand {
    #[argh(subcommand)]
    subcommand: SessionSubcommand,
}

#[derive(FromArgs)]
#[argh(subcommand)]
enum SessionSubcommand {
    List(SessionList),
    Login(SessionLogin),
    Logout(SessionLogout),
    Rename(SessionRename),
    Verify(SessionVerify),
}

#[derive(FromArgs)]
#[argh(subcommand, name = "list")]
/// List currently-logged-in accounts
struct SessionList {
    #[argh(switch, short = 'j')]
    /// display session list as JSON rather than as human-readable text
    json: bool,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "login")]
/// Log in a new account, creating a new session
struct SessionLogin {
    #[argh(positional)]
    /// user id (of the form @alice:example.com) to be logged in
    user_id: String,
    #[argh(positional)]
    /// optional session name for use in place of the default randomized one
    session_name: Option<String>
}

#[derive(FromArgs)]
#[argh(subcommand, name = "logout")]
/// Log out a previously-logged-in account
struct SessionLogout {
    #[argh(positional)]
    /// user id (of the form @alice:example.com) to be logged out
    user_id: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "rename")]
/// Rename a logged-in session
struct SessionRename {
    #[argh(positional)]
    /// user id (of the form @alice:example.com) to be renamed
    user_id: String,
    #[argh(positional)]
    /// new name for session
    session_name: String,
}

#[derive(FromArgs)]
#[argh(subcommand, name = "verify")]
/// Verify a logged-in session for purposes of E2E encryption
struct SessionVerify {
    #[argh(positional)]
    /// user id (of the form @alice:example.com) to verify your session with
    user_id: String,
}

///////////////////////
//   Non-arg types   //
///////////////////////

#[derive(Serialize)]
struct PrintableRoom {
    name: Option<String>,
    alias: Option<String>,
    id: String,
}

impl PrintableRoom {
    fn from_room_info(room_info: RoomWithCachedInfo) -> Self {
        Self {
            name: room_info.name,
            alias: room_info.canonical_alias.map(|alias| alias.to_string()),
            id: room_info.id.to_string(),
        }
    }
}

#[derive(Serialize)]
struct PrintableSession {
    user_id: String,
    name: String,
}

/////////////////
//   Helpers   //
/////////////////

async fn handle_verification_request(verification_request: VerificationRequest) -> anyhow::Result<()> {
    verification_request.accept().await?;
    let mut verification_state_stream = verification_request.changes();
    while let Some(state) = verification_state_stream.next().await {
        match state {
            VerificationRequestState::Transitioned { verification } => {
                if let Verification::SasV1(sas_verification) = verification {
                    sas_verification.accept_with_settings(AcceptSettings::with_allowed_methods(vec![ShortAuthenticationString::Decimal])).await?;
                    let mut sas_verification_state_stream = sas_verification.changes();
                    while let Some(state) = sas_verification_state_stream.next().await {
                        #[allow(clippy::single_match)] // Temp for development
                        match state {
                            SasState::KeysExchanged {decimals, ..} => {
                                println!("Attempting verification. SAS decimals: {}, {}, {}", decimals.0, decimals.1, decimals.2);
                                println!("Do these decimals match those shown on the other side of the verification? (Y)es/(N)o/(C)ancel");
                                loop {
                                    let input: String = text_io::read!();
                                    match input.trim().to_ascii_lowercase().as_ref() {
                                        "y" | "yes" => {
                                            sas_verification.confirm().await?;
                                            println!("Verified. Make sure verification has finished on the other end, then ctrl-c out.");
                                            // Add checking to ensure verification succeeds on the remote end as well before breaking
                                            break
                                        }
                                        "n" | "no" => {
                                            sas_verification.mismatch().await?;
                                            println!("Verification failed due to string mismatch.");
                                            break
                                        }
                                        "c" | "cancel" => {
                                            sas_verification.cancel().await?;
                                            println!("Canceled verification attempt.");
                                            break
                                        }
                                        _ => println!("Input '{}' not recognized. Please try again.", input),
                                    }
                                }

                            }
                            _ => (),
                        }
                    }
                } else {
                    println!("Received verification attempt of type other than SAS V1. Trace CLI can't handle QR code verification, and Trace's developers are unaware of any verification types aside from SAS V1 and QR, so this verification attempt has been aborted.");
                }
            }
            VerificationRequestState::Cancelled(info) => {
                println!("Verification cancelled. Cancel info: {:?}", info);
                break
            }
            VerificationRequestState::Done => {
                println!("Verification done.");
                break
            }
            _ => (),
        }
    }

    Ok(())
}

//////////////
//   Main   //
//////////////

async fn export(config: Export, sessions_file: &SessionsFile, dirs: &ProjectDirs) -> anyhow::Result<()> {
    let store_path = PathBuf::from(dirs.data_local_dir()).join(user_id_to_crypto_store_path(&config.user_id));
    let mut export_formats = HashSet::new();
    for format in config.formats {
        match format.to_lowercase().as_ref() {
            "json" | ".json" => export_formats.insert(ExportOutputFormat::Json),
            "txt" | ".txt" => export_formats.insert(ExportOutputFormat::Txt),
            _ => panic!("Received invalid format specifier {} on export command. Valid options are 'json' and 'txt'.", format), // Add real error-handling here. (It'd be nice if argh allowed more direct handling of this; track https://github.com/google/argh/issues/138 in case it eventually does.)
        };
    }
    if export_formats.is_empty() {
        export_formats.insert(ExportOutputFormat::Json);
    }

    let export_room_count = config.rooms.len();
    if export_room_count == 0 {
        println!("Successfully exported 0 rooms. (This may not be what you meant to do.)");
        return Ok(()); // Plausibly replace with an error once I've got real error-handling
    }

    let client = nonfirst_login(&config.user_id, sessions_file, &store_path).await?;
    client.sync_once(SyncSettings::new().set_presence(PresenceState::Offline)).await?;
    trace::export(&client, config.rooms, config.output, export_formats).await?;

    println!("Successfully exported {} rooms.", export_room_count);

    Ok(())
}

async fn list_rooms(config: ListRooms, sessions_file: &SessionsFile, dirs: &ProjectDirs) -> anyhow::Result<()> {
    let store_path = PathBuf::from(dirs.data_local_dir()).join(user_id_to_crypto_store_path(&config.user_id));
    let normalized_user_id = add_at_to_user_id_if_applicable(&config.user_id);
    let client = nonfirst_login(&normalized_user_id, sessions_file, &store_path).await?;
    client.sync_once(SyncSettings::new().set_presence(PresenceState::Offline)).await?;

    let printable_rooms = trace::get_rooms_info(&client).await?
        .into_iter()
        .map(PrintableRoom::from_room_info)
        .collect::<Vec<PrintableRoom>>();
    if config.json {
        println!("{}", serde_json::to_string(&printable_rooms).unwrap());
    } else {
        println!("Rooms joined by {}:", normalized_user_id);
        for room in printable_rooms {
            let room_name = match room.name {
                Some(name) => name,
                None => String::from("[Unnamed]"),
            };
            let room_alias = match room.alias {
                Some(alias) => alias,
                None => String::from("[No canonical alias]"),
            };
            println!("{} | {} | {}", room_name, room_alias, room.id) // Replace with properly-justified table-formatting in the future
        }
    }

    Ok(())
}

async fn session_list(config: SessionList, sessions_file: &SessionsFile, dirs: &ProjectDirs) -> anyhow::Result<()> {
    let printable_sessions = trace::list_sessions(sessions_file, dirs).await?
        .into_iter()
        .map(|(user_id, name)| PrintableSession {
            user_id,
            name,
        })
        .collect::<Vec<PrintableSession>>();
    if config.json {
        println!("{}", serde_json::to_string(&printable_sessions).unwrap());
    } else if !printable_sessions.is_empty() {
        println!("Currently-logged-in sessions:");
        for session in printable_sessions {
            println!("{} | {}", session.user_id, session.name) // Replace with properly-justified table-formatting in the future
        }
    } else {
        println!("You have no sessions currently logged in.");
    }

    Ok(())
}

async fn session_login(config: SessionLogin, sessions_file: &mut SessionsFile, dirs: &ProjectDirs) -> anyhow::Result<()> {
    let store_path = PathBuf::from(dirs.data_local_dir()).join(user_id_to_crypto_store_path(&config.user_id));
    let normalized_user_id = add_at_to_user_id_if_applicable(&config.user_id);
    if sessions_file.get(&normalized_user_id).is_ok() {
        panic!("Tried to log into account {}, but you already have a session logged into this account.", &normalized_user_id); // Replace this with real error-handling.
    }

    println!("Please input password for account {}.", &normalized_user_id);
    let password = read_password().unwrap();
    println!("Attempting login to account {}.", &normalized_user_id);

    let user = UserId::parse(&normalized_user_id)?;
    let client = Client::builder().server_name(user.server_name()).sqlite_store(store_path, None).build().await?; // Is this doing the store config right?

    trace::first_login(&client, sessions_file, &normalized_user_id, &password, config.session_name).await?;

    println!("Successfully logged into account {}.", normalized_user_id);

    Ok(())
}

async fn session_logout(config: SessionLogout, sessions_file: &mut SessionsFile, dirs: &ProjectDirs) -> anyhow::Result<()> {
    let store_path = PathBuf::from(dirs.data_local_dir()).join(user_id_to_crypto_store_path(&config.user_id));
    let normalized_user_id = add_at_to_user_id_if_applicable(&config.user_id);

    let successful_remote_logout = match nonfirst_login(&config.user_id, sessions_file, &store_path).await {
        Ok(client) => match client.matrix_auth().logout().await {
            Ok(_) => true,
            Err(e) => {
                println!("Couldn't connect cilent to server due to error '{}'. Logging out on client side only. You may want to double-check {}'s sessions list in a different client just in case the session is still logged in on the server side.", e, normalized_user_id);
                false
            }
        },
        Err(e) => {
            println!("Couldn't connect cilent to server due to error '{}'. Logging out on client side only. You may want to double-check {}'s sessions list in a different client just in case the session is still logged in on the server side.", e, normalized_user_id);
            false
        }
    };
    trace::logout_local(&config.user_id, sessions_file, &store_path)?;
    if successful_remote_logout {
        println!("Successfully logged out of account {}.", normalized_user_id);
    } else {
        println!("Successfully logged out of account {} on the client side.", normalized_user_id);
    }

    Ok(())
}

async fn session_rename(config: SessionRename, sessions_file: &SessionsFile, dirs: &ProjectDirs) -> anyhow::Result<()> {
    let store_path = PathBuf::from(dirs.data_local_dir()).join(user_id_to_crypto_store_path(&config.user_id));
    let client = nonfirst_login(&config.user_id, sessions_file, &store_path).await?;
    trace::rename_session(&client, &config.session_name).await?;

    println!("Successfully renamed account {}'s session to '{}'.", add_at_to_user_id_if_applicable(&config.user_id), config.session_name);

    Ok(())
}

async fn session_verify(config: SessionVerify, sessions_file: &SessionsFile, dirs: &ProjectDirs) -> anyhow::Result<()> {
    println!("Warning: verification, although technically implemented, is currently a mess. You will need to manually ctrl-c out of the verification flow once finished.");
    // Add a branch for if no incoming verification request is captured in the sync, to produce an outgoing one.
    let store_path = PathBuf::from(dirs.data_local_dir()).join(user_id_to_crypto_store_path(&config.user_id));
    let client = nonfirst_login(&config.user_id, sessions_file, &store_path).await?;
    let encryption = client.encryption();
    client.add_event_handler(|event: ToDeviceKeyVerificationRequestEvent| async move {
        let user_id = event.sender;
        let flow_id = event.content.transaction_id;
        match encryption.get_verification_request(&user_id, flow_id).await {
            None => (),
            Some(verification_request) => {
                tokio::spawn(handle_verification_request(verification_request)); // Asynchronousness is needed to keep the sync going, which is needed for the verification flow to go through successfully
            }
        }
    });

    client.sync(SyncSettings::new().set_presence(PresenceState::Offline)).await?; // Figure out how to stop syncing once the verification is done

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let dirs = ProjectDirs::from("", "", "Trace").unwrap(); // Figure out qualifier and organization
    let mut sessions_file = SessionsFile::open([dirs.data_local_dir(), Path::new("sessions.json")].iter().collect());

    let args: Args = argh::from_env();
    match args.subcommand {
        RootSubcommand::Export(config) => export(config, &sessions_file, &dirs).await?,
        RootSubcommand::ListRooms(config) => list_rooms(config, &sessions_file, &dirs).await?,
        RootSubcommand::Session(s) => match s.subcommand {
            SessionSubcommand::List(config) => session_list(config, &sessions_file, &dirs).await?,
            SessionSubcommand::Login(config) => session_login(config, &mut sessions_file, &dirs).await?,
            SessionSubcommand::Logout(config) => session_logout(config, &mut sessions_file, &dirs).await?,
            SessionSubcommand::Rename(config) => session_rename(config, &sessions_file, &dirs).await?,
            SessionSubcommand::Verify(config) => session_verify(config, &sessions_file, &dirs).await?,
        }
    };

    Ok(())
}
