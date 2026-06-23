## Offline Caching

- key of a cached message = hash(hash(last_known_chat_history), own_peer_id)
- we break the assumption that key of value == hash(value)
- value is encrypted message (including metadat etc.)
- recipient must be able to calclate the id of the next message based on the content of the last decrypted (cached) message
- consider: when sending multiple messages store them as batch?