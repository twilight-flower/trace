use std::{
    cmp::Ordering,
    fs::{
        create_dir_all,
        read_to_string,
        remove_dir_all,
        write,
    },
    path::{
        Path,
        PathBuf,
    },
};

use directories::ProjectDirs;
use futures::future::join_all;
use matrix_sdk::{
    Client, Room, SessionMeta, authentication::{SessionTokens, matrix::MatrixSession}, config::SyncSettings, ruma::{
        OwnedRoomAliasId, OwnedRoomId, UserId, api::client::session::get_login_types::v3::LoginType, presence::PresenceState
    }, store::RoomLoadSettings
};
use serde::{
    Deserialize,
    Serialize,
};

pub mod export;

////////////////////
//   Re-exports   //
////////////////////

pub use export::{
    export,
    ExportOutputFormat,
};

///////////////
//   Types   //
///////////////

#[derive(Clone, Deserialize, Serialize)]
pub struct Session {
    pub user_id: String,
    pub device_id: String,
    pub access_token: String,
    pub refresh_token: Option<String>,
}

pub struct SessionsFile {
    path: PathBuf,
    pub sessions: Vec<Session>,
}

impl SessionsFile {
    pub fn open(path: PathBuf) -> Self {
        if let Ok(file) = read_to_string(&path) {
            let sessions = serde_json::from_str(&file).expect("Sessions file is invalid JSON."); // Replace with better error-handling
            Self {
                path,
                sessions,
            }
        } else {
            create_dir_all(path.parent().expect("Tried to open root as sessions file. (This should never happen.")).unwrap();
            write(&path, "[]").unwrap();
            Self {
                path,
                sessions: Vec::new(),
            }
        }
    }

    pub fn get(&self, user_id: &str) -> Result<Session, String> {
        match self.sessions.iter().find(|session| session.user_id == user_id) {
            Some(session) => Ok(session.clone()),
            None => Err(format!("Couldn't find currently-existing login session for user_id {}.", user_id))
        }
    }

    pub fn delete_session(&mut self, user_id: &str) -> Result<(), String> {
        match self.sessions.iter().position(|session| session.user_id == user_id) {
            Some(session_index) => {
                self.sessions.remove(session_index);
                self.write();
                Ok(())
            }
            None => Err(format!("Couldn't find currently-existing login session for user_id {}.", user_id))
        }
    }

    pub fn new_session(&mut self, session: Session) -> Result<(), String> {
        if !self.sessions.iter().any(|preexisting_session| preexisting_session.user_id == session.user_id) {
            self.sessions.push(session);
            self.write();
            Ok(())
        } else {
            Err(format!("Tried to create new session with user_id {}, but you already have a logged-in session with that user ID.", session.user_id))
        }
    }

    pub fn write(&self) {
        let updated_file = serde_json::to_string(&self.sessions).unwrap();
        write(&self.path, updated_file).unwrap();
    }
}

pub struct RoomWithCachedInfo {
    pub id: OwnedRoomId,
    pub name: Option<String>,
    pub canonical_alias: Option<OwnedRoomAliasId>,
    pub alt_aliases: Vec<OwnedRoomAliasId>,
    pub room: Room,
}

////////////////////////
//   Shared helpers   //
////////////////////////

pub fn add_at_to_user_id_if_applicable(user_id: &str) -> String {
    if user_id.starts_with('@') {
        String::from(user_id)
    } else {
        format!("@{}", user_id)
    }
}

pub fn user_id_to_crypto_store_path(user_id: &str) -> PathBuf {
    let atless_user_id = if user_id.starts_with('@') {
        user_id.chars().skip(1).collect()
    } else {
        String::from(user_id)
    };

    let mut store_path = PathBuf::new();
    for component in atless_user_id.split(':').rev() {
        store_path.push(component);
    }
    store_path
}

pub async fn nonfirst_login(user_id: &str, sessions_file: &SessionsFile, store_path: &Path) -> anyhow::Result<Client> {
    let normalized_user_id = add_at_to_user_id_if_applicable(user_id);
    let session = sessions_file.get(&normalized_user_id).unwrap();
    let user = UserId::parse(&session.user_id)?;
    let client = Client::builder().server_name(user.server_name()).sqlite_store(store_path, None).build().await?;
    client.matrix_auth().restore_session(MatrixSession {
        meta: SessionMeta {
            user_id: user,
            device_id: session.device_id.into(),
        },
        tokens: SessionTokens {
            access_token: session.access_token,
            refresh_token: session.refresh_token,
        }
    }, RoomLoadSettings::default()).await?;
    client.encryption().wait_for_e2ee_initialization_tasks().await;

    Ok(client)
}

///////////////////////////////
//   Shared core functions   //
///////////////////////////////

pub async fn first_login(client: &Client, sessions_file: &mut SessionsFile, user_id: &str, password: &str, session_name: Option<String>) -> anyhow::Result<()> {
    let auth = client.matrix_auth();
    let supported_login_types = auth.get_login_types().await?.flows;
    let login_result = if supported_login_types.iter().any(|login_type| matches!(login_type, LoginType::Password(_))) {
        let login_request = auth.login_username(user_id, password);
        if let Some(name) = session_name {
            login_request.initial_device_display_name(&name).send().await?
        } else {
            // Do we want some sort of default name here?
            login_request.send().await?
        }
    } else {
        panic!("Attempted login to a server which lacks password-based login support. (SSO support will be added eventually.)");
    };

    sessions_file.new_session(Session {
        user_id: login_result.user_id.to_string(),
        device_id: login_result.device_id.to_string(),
        access_token: login_result.access_token.to_string(),
        refresh_token: login_result.refresh_token,
    }).unwrap();

    client.encryption().wait_for_e2ee_initialization_tasks().await;
    client.sync_once(SyncSettings::new().set_presence(PresenceState::Offline)).await?;

    Ok(())
}

pub async fn logout_full(client: &Client, sessions_file: &mut SessionsFile, store_path: &Path) -> anyhow::Result<()> {
    client.matrix_auth().logout().await?;
    remove_dir_all(store_path)?;
    let store_path_parent = store_path.parent().unwrap();
    if store_path_parent.read_dir()?.next().is_none() {
        remove_dir_all(store_path_parent)?;
    }
    sessions_file.delete_session(client.user_id().unwrap().as_ref()).unwrap();

    Ok(())
}

pub fn logout_local(user_id: &str, sessions_file: &mut SessionsFile, store_path: &Path) -> anyhow::Result<()> {
    remove_dir_all(store_path)?;
    let store_path_parent = store_path.parent().unwrap();
    if store_path_parent.read_dir()?.next().is_none() {
        remove_dir_all(store_path_parent)?;
    }
    sessions_file.delete_session(user_id).unwrap();

    Ok(())
}

pub async fn list_sessions(sessions_file: &SessionsFile, dirs: &ProjectDirs) -> anyhow::Result<Vec<(String, String)>> {
    let mut sessions_info = join_all(sessions_file.sessions.iter().map(|session| async {
        let store_path = PathBuf::from(dirs.data_local_dir()).join(user_id_to_crypto_store_path(&session.user_id));
        let client = nonfirst_login(&session.user_id, sessions_file, &store_path).await?;
        let device_list = client.devices().await?.devices;
        let device_name = device_list.into_iter().find(|device| device.device_id == session.device_id).unwrap().display_name.unwrap_or_else(|| String::from("[Unnamed]"));
        anyhow::Result::<(String, String)>::Ok((session.user_id.clone(), device_name))
    })).await.into_iter().collect::<anyhow::Result<Vec<(String, String)>, _>>()?;
    sessions_info.sort_by(|(user_id_1, _display_name_1), (user_id_2, _display_name_2)| user_id_1.cmp(user_id_2)); // sort_by_key doesn't work here for weird lifetime reasons

    Ok(sessions_info)
}

pub async fn rename_session(client: &Client, new_session_name: &str) -> anyhow::Result<()> {
    client.rename_device(client.device_id().unwrap(), new_session_name).await?;

    Ok(())
}

pub async fn get_rooms_info(client: &Client) -> anyhow::Result<Vec<RoomWithCachedInfo>> {
    let mut rooms_info = client.joined_rooms().into_iter().map(|room| RoomWithCachedInfo {
        id: room.room_id().to_owned(),
        name: room.name(),
        canonical_alias: room.canonical_alias(),
        alt_aliases: room.alt_aliases(),
        room,
    }).collect::<Vec<RoomWithCachedInfo>>();
    rooms_info.sort_by(|room_1, room_2| match (&room_1.name, &room_2.name) {
        (Some(name_1), Some(name_2)) => name_1.cmp(name_2),
        (Some(_name), None) => Ordering::Greater,
        (None, Some(_name)) => Ordering::Less,
        (None, None) => match (&room_1.canonical_alias, &room_2.canonical_alias) {
            (Some(alias_1), Some(alias_2)) => alias_1.cmp(alias_2),
            (Some(_alias), None) => Ordering::Greater,
            (None, Some(_alias)) => Ordering::Less,
            (None, None) => room_1.id.cmp(&room_2.id),
        },
    });

    Ok(rooms_info)
}
