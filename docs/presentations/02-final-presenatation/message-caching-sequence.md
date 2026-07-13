sequenceDiagram
    autonumber
    actor Alice
    participant Network as Network (DHT)
    actor Bob

    rect rgb(226, 245, 231)
        Note over Alice,Bob: 1 - Normal chat — both online
        Alice->>Bob: chat_msg_req (chat init + shared secret)
        Bob-->>Alice: ack
    end

    rect rgb(255, 244, 224)
        Note over Alice,Bob: 2 - Caching — Bob offline
        Alice-xBob: chat_msg_req
        Note right of Alice: timeout<br/>location_key = hash(chat_head + Alice_id)
        Alice->>Network: store_req(location_key, encrypted msg)
    end

    rect rgb(224, 238, 255)
        Note over Alice,Bob: 3 - Retrieval — Bob back online
        Note left of Bob: location_key = hash(chat_head + Alice_id)
        Bob->>Network: find_value(location_key)
        Network-->>Bob: encrypted msg
        Note left of Bob: decrypt + verify signature
        Bob->>Network: find_value(next location_key)
        Network-->>Bob: no value — done
    end