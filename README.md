# TCP/IP

> This is a user-land implementation of the TCP/IP protocol using the Linux TAP interface


## TODOs/Ideas

<!-- - Have a single outgoing queue that handles both normal transmissions and retransmissions, so we eliminate an additional thread
    - Each segment would have a RTO with new segments have RTO = 0, while retransmitted segments would have a non-zero RTO (increasing with each retransmission).
    - Insertions should be sorted by RTO (insertion sort should not be so computationally expensive...) -->

- Review the whole implementation to fix mistakes of RFC 793 by following RFC 1122 and later erratas

- Add an empty queue signal
    - Each connection can be signaled that all the segments were sent (and ACKed), so it can close
- Optimize transmission queue
    - maybe have some form of poll on multiple connections to efficiently select the connection and segment to transmit instead of using a loop on the queue

