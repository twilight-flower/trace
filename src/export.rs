use std::collections::{
    HashMap,
    HashSet,
};
use std::fs::{
    create_dir_all,
    write,
};
use std::path::PathBuf;

use crate::{
    get_rooms_info,
    RoomWithCachedInfo,
};

use chrono::{DateTime, SecondsFormat};
use matrix_sdk::{
    deserialized_responses::TimelineEvent,
    room::MessagesOptions,
    ruma::{
        events::{
            room::message::MessageType,
            AnyMessageLikeEvent,
            AnyTimelineEvent,
        },
        UserId
    },
    Client,
};

///////////////
//   Types   //
///////////////

#[derive(PartialEq, Eq, Hash)]
pub enum ExportOutputFormat {
    Json,
    Txt,
}

enum RoomIndexRetrievalError {
    MultipleRoomsWithSpecifiedName(Vec<String>),
    NoRoomsWithSpecifiedName,
}

//////////////
//   Main   //
//////////////

fn get_room_index_by_identifier(rooms_info: &[RoomWithCachedInfo], identifier: &str) -> Result<usize, RoomIndexRetrievalError> {
    if let Some(index) = rooms_info.iter().position(|room_info| room_info.id == identifier) {
        Ok(index)
    } else if let Some(index) = rooms_info.iter().position(|room_info| room_info.canonical_alias.as_ref().is_some_and(|alias| alias == identifier)) {
        Ok(index)
    } else if let Some(index) = rooms_info.iter().position(|room_info| room_info.alt_aliases.iter().any(|alias| alias == identifier)) {
        Ok(index)
    } else {
        let name_matches = rooms_info.iter().filter(|room_info| room_info.name.as_ref().is_some_and(|name| name == identifier)).collect::<Vec<&RoomWithCachedInfo>>();
        match name_matches.len() {
            0 => Err(RoomIndexRetrievalError::NoRoomsWithSpecifiedName),
            1 => Ok(rooms_info.iter().position(|room_info| room_info.name.as_ref().is_some_and(|name| name  == identifier)).unwrap()),
            _ => Err(RoomIndexRetrievalError::MultipleRoomsWithSpecifiedName(name_matches.iter().map(|room_info| room_info.id.to_string()).collect())),
        }
    }
}

fn format_export_filename(room_info: &RoomWithCachedInfo) -> String {
    let (nonserver_id_component, server) = room_info.id.as_str().split_once(':').unwrap();
    match (&room_info.name, &room_info.canonical_alias) {
        (Some(name), Some(alias)) => format!("{} [{}, {}, {}]", name, alias.as_str().split_once(':').unwrap().0, nonserver_id_component, server),
        (Some(name), None) => format!("{} [{}, {}]", name, nonserver_id_component, server),
        (None, Some(alias)) => format!("{} [{}, {}]", alias.as_str().split_once(':').unwrap().0, nonserver_id_component, server),
        (None, None) => format!("{} [{}]", nonserver_id_component, server),
    }
}

fn messages_to_json(events: &Vec<TimelineEvent>) -> String {
    // Possibly add more secondary-representations-of-events here, analogous to e.g. the display-name-retrieval and datetime-formatting and so forth in the txt output?
    // Also possibly some metadata analogous to what gets output at the head of DiscordChatExporter's JSON exports?
    let mut events_to_export = Vec::new();

    for event in events {
        let event_serialized = event.event.deserialize_as::<serde_json::Value>().expect("Failed to deserialize a message to JSON value. (This is surprising.)"); // Add real error-handling here
        events_to_export.push(event_serialized);
    }

    serde_json::to_string_pretty(&events_to_export).unwrap()
}

async fn user_id_to_string_representation(user_ids_to_string_representations: &mut HashMap<String, String>, room_info: &RoomWithCachedInfo, event_sender_id: &UserId) -> anyhow::Result<String> {
    let event_sender_id_string = event_sender_id.to_string();
    match user_ids_to_string_representations.get(&event_sender_id_string) {
        Some(string_representation) => Ok(string_representation.clone()),
        None => match room_info.room.get_member_no_sync(event_sender_id).await? {
            Some(room_member) => {
                let string_representation = match room_member.display_name() {
                    Some(display_name) => format!("{} ({})", display_name, event_sender_id_string),
                    None => event_sender_id_string.clone(),
                };
                user_ids_to_string_representations.insert(event_sender_id_string.clone(), string_representation);
                Ok(user_ids_to_string_representations.get(&event_sender_id_string).unwrap().clone())
            }
            None => {
                user_ids_to_string_representations.insert(event_sender_id_string.clone(), event_sender_id_string.clone());
                Ok(event_sender_id_string)
            },
        },
    }
}

async fn messages_to_txt(events: &Vec<TimelineEvent>, room_info: &RoomWithCachedInfo) -> anyhow::Result<String> {
    let mut user_ids_to_string_representations: HashMap<String, String> = HashMap::new();
    let mut room_export = String::new();

    for event in events {
        let event_deserialized = match event.event.deserialize() {
            Ok(event_deserialized) => event_deserialized,
            Err(_) => {
                // Add more nuanced error-handling here; it seems like a lot of these are in fact redacted messages, just weirdly-formed ones that don't deserialize right?
                room_export.push_str("[Message skipped due to deserialization failure]\n");
                continue
            }
        };

        let event_timestamp_millis = event_deserialized.origin_server_ts().0.into();
        let event_timestamp_string_representation = DateTime::from_timestamp_millis(event_timestamp_millis).unwrap_or_else(|| panic!("Found message with millisecond timestamp {}, which can't be converted to datetime.", event_timestamp_millis)).to_rfc3339_opts(SecondsFormat::Millis, true); // Add real error-handling, and also an option to use local time zones

        let event_sender_id = event_deserialized.sender();
        let event_sender_string_representation = user_id_to_string_representation(&mut user_ids_to_string_representations, room_info, event_sender_id).await?;

        let event_prefix = format!("[{}] {}:", event_timestamp_string_representation, event_sender_string_representation);

        let event_stringified = match &event_deserialized {
            AnyTimelineEvent::MessageLike(e) => match e {
                AnyMessageLikeEvent::RoomMessage(e) => match &e.as_original() {
                    Some(unredacted_room_message) => match &unredacted_room_message.content.msgtype {
                        // Possibly revisit here at some point to add more detail beyond the body into various of these formats
                        MessageType::Audio(e) => format!("{} [Audio; textual representation: {}]", event_prefix, &e.body),
                        MessageType::Emote(e) => format!("{} *{}*", event_prefix, &e.body), // Think harder about whether asterisks are the correct representation here
                        MessageType::File(e) => format!("{} [File; textual representation: {}]", event_prefix, &e.body), // In the longer term maybe include filename directly? But currently it seems like the textual representation is the main thing that's actually used to encode the filename
                        MessageType::Image(e) => format!("{} [Image; textual representation: {}]", event_prefix, &e.body),
                        MessageType::Location(e) => format!("{} [Location; geo URI: {}; textual representation: {}]", event_prefix, &e.geo_uri, &e.body),
                        MessageType::Notice(e) => format!("{} [{}]", event_prefix, &e.body), // Think harder about whether brackets are the correct representation here
                        MessageType::ServerNotice(e) => format!("{} [Server notice: {}]", event_prefix, &e.body),
                        MessageType::Text(e) => format!("{} {}", event_prefix, &e.body),
                        MessageType::Video(e) => format!("{} [Video; textual representation: {}]", event_prefix, &e.body),
                        MessageType::VerificationRequest(e) => format!("{} [Verification request sent to {}]", event_prefix, user_id_to_string_representation(&mut user_ids_to_string_representations, room_info, &e.to).await?),
                        _ => String::from("[Message of unrecognized type]"),
                    }
                    None => format!("{} [Redacted message]", event_prefix),
                },
                _ => String::from("[Placeholder message-like]"),
            },
            AnyTimelineEvent::State(_e) => String::from("[Placeholder state-like]"),
        };
        room_export.push_str(&format!("{}\n", event_stringified))
    }

    Ok(room_export)
}

pub async fn export(client: &Client, rooms: Vec<String>, output_path: Option<PathBuf>, formats: HashSet<ExportOutputFormat>) -> anyhow::Result<()> {
    if let Some(path) = output_path.as_ref() {
        if path.exists() {
            if !path.is_dir() {
                // Add real error-handling here
                panic!("Output path {} isn't a directory.", path.display());
            }
        } else {
            create_dir_all(path).unwrap();
        }
    }

    let accessible_rooms_info = get_rooms_info(client).await?; // This should be possible to optimize out for request-piles without names included, given client.resolve_room_alias and client.get_room. Although that might end up actually costlier if handled indelicately, since it'll involve more serial processing.

    for room_identifier in rooms {
        let room_to_export_info = match get_room_index_by_identifier(&accessible_rooms_info, &room_identifier) {
            Ok(index) => &accessible_rooms_info[index],
            Err(e) => match e {
                // This is currently CLI-biased; modify it to return error-info in a more neutral way
                RoomIndexRetrievalError::MultipleRoomsWithSpecifiedName(room_ids) => {
                    println!("Found more than one room accessible to {} with name {}. Room IDs: {:?}", client.user_id().unwrap(), room_identifier, room_ids);
                    continue
                },
                RoomIndexRetrievalError::NoRoomsWithSpecifiedName => {
                    println!("Couldn't find any rooms accessible to {} with name {}.", client.user_id().unwrap(), room_identifier);
                    continue
                },
            }
        };

        let mut events = Vec::new();
        let mut last_end_token = None;
        let mut total_messages = 0;
        loop {
            let mut messages_options = MessagesOptions::forward().from(last_end_token.as_deref());
            messages_options.limit = 1_000_u16.into(); // On an initial test, this seems to be a server-side limit, at least on matrix.org. Worth setting higher just in case other servers are less limited?
            let mut messages = room_to_export_info.room.messages(messages_options).await?;
            let messages_length = messages.chunk.len();
            total_messages += messages_length;
            if messages_length == 0 || total_messages > 10_000_000 {
                break
            }
            events.append(&mut messages.chunk);
            last_end_token = messages.end;
        }

        let base_output_path = output_path.clone().unwrap_or_default();
        let base_output_filename = format_export_filename(room_to_export_info);
        if formats.contains(&ExportOutputFormat::Json) {
            let json_output_file = messages_to_json(&events);
            let mut json_output_path_buf = base_output_path.clone();
            json_output_path_buf.push(format!("{}.json", base_output_filename));
            write(json_output_path_buf, json_output_file).unwrap();
        }
        if formats.contains(&ExportOutputFormat::Txt) {
            let txt_output_file = messages_to_txt(&events, room_to_export_info).await?;
            let mut txt_output_path_buf = base_output_path.clone();
            txt_output_path_buf.push(format!("{}.txt", base_output_filename));
            write(txt_output_path_buf, txt_output_file).unwrap();
        }
    }

    Ok(())
}
