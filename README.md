# TA-endpoint
TA-endpoint is the endpoint of tangle-accelerator. TA-endpoint would be running on a resource-constrained network connectivity module. The embedded devices can send messages to blockchain network (Tangle) with a connectivity module loaded TA-endpoint. The message would be transmitted to connectivity module through UART. Message would be encrypted and send to tangle.

# Streaming Message Channel Implementation
The encrypted message would be sent to Tangle with a streaming message channel API. The streaming message channel API would ensure the order of messages in the channel. User who wants to fecth/send message to Tangle needs to provide `data_id`, `key` and `protocol` to identify a specific message.
A message sent by TA-endpoint needs to be encrypted locally which avoids message being peeked and modified. 

# How to use
```
$ git clone --recursive https://github.com/DLTcollab/TA-endpoint 
$ make -j$(nproc)
```