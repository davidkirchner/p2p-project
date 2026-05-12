# Presentation Notes

## Slide 1: Objectives

* **Core Goal:** The primary objective is to build a functional decentralized messenger without relying on central servers.
* **Security:** All communication must be end-to-end encrypted so that only the intended recipients can read the messages.
* **Asynchronous Communication:** A critical feature we want to support is sending messages to offline peers. Because there is no central server, we have to figure out how to reliably deliver these messages once the user comes back online.
* **Stretch Goals:** If time permits, we plan to implement more complex features, such as file-sharing capabilities and group chat functionality.

## Slide 2: Technical Challenges
* **Routing/Addressing:** First, we need a reliable way to map usernames or user-ids to consistently changing IP addresses.
* **Identity:** We also need a system for verifiable peer identification—ensuring that the person you are talking to is actually who they claim to be using public key cryptography.
* **Offline Messaging:** As mentioned, caching messages for offline peers is a unique challenge. We will need to design a system where peers temporarily store encrypted messages for others and resend them when the recipient comes back online. There will be quite a few cases to handle here:
 - caching peers going offline,
 - reassemble the chat history from cached messages
  redundancy,
* **Security & Abuse:** We want to protect or at least try to mitigate attack on the network, such as spam, cache abuse (many messages or large messages), cache lifetimes, not following protocol, freeriders and malicious nodes
* **Metadata Privacy:** Finally, while end-to-end encryption hides the *content* of the messages, hiding the *metadata* - meaning who is communicating with whom and when - is quite a hard problem. We want to explore techniques to minimize metadata to a reasonable extent. Especially interesting is this feature in combination with the message caching, since encrypted receiver adresses make message retrieval very non-trivial.
