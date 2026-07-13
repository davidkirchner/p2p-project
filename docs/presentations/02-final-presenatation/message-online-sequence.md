sequenceDiagram
    autonumber
    actor Alice
    actor Bob

    rect rgb(226, 245, 231)
        Note over Alice,Bob: Normal chat — both online
        Alice->>Bob: chat_msg_req (chat init + shared secret)
        Bob-->>Alice: ack
    end
