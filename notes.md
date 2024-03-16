
## Features 

#### Packet Strider adaptation
- [X] Determine keystroke size
- [X] Determine login prompt size
- [X] Determine protocols
- [X] Determine hassh
- [ ] Detect `-R` option 
- [X] Detect login attempts
- [ ] Detect key accept into `known_hosts`
- [ ] Detect Agent Forwarding 
- [ ] Detect file exfiltration
- [ ] Detect file infiltration 
- [ ] Reverse SSH ???
- [ ] Classify keystrokes

#### New features
- [X] Detect key offers / accepts
- [X] Identify key types 
- [ ] Output latencies into processable format
- [ ] Real-time monitoring

## To-do's 
> Most `TODO`'s are in the codebase, as comments. The rest, more general ones, are here, so that I don't forget.
- [ ] Refactor code into proper files (`scan.rs`, etc.)
- [ ] Refactor functions to public / private, as needed
- [ ] Write documentation (?)
- [ ] More test cases with serialised packet data from PCAPs 
- [ ] Coverage test (?) 

## Ciphers

The cipher struct is defined as follows: 

```c
struct sshcipher {
	char	*name;
	u_int	block_size;
	u_int	key_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	flags;
#define CFLAG_CBC		(1<<0)
#define CFLAG_CHACHAPOLY	(1<<1)
#define CFLAG_AESCTR		(1<<2)
#define CFLAG_NONE		(1<<3)
#define CFLAG_INTERNAL		CFLAG_NONE /* Don't use "none" for packets */
#ifdef WITH_OPENSSL
	const EVP_CIPHER	*(*evptype)(void);
#else
	void	*ignored;
#endif
};
```

Then, the common [ciphers](https://github.com/openssh/openssh-portable/blob/2f9d2af5cb19905d87f37d1e11c9f035ac5daf3b/cipher.c#L99) are defined as follows:

```c
{ "aes128-cbc",                     16, 16, 0,  0, CFLAG_CBC, EVP_aes_128_cbc },
{ "aes192-cbc",                     16, 24, 0,  0, CFLAG_CBC, EVP_aes_192_cbc },
{ "aes256-cbc",                     16, 32, 0,  0, CFLAG_CBC, EVP_aes_256_cbc },
{ "aes128-ctr",                     16, 16, 0,  0, 0, EVP_aes_128_ctr },
{ "aes192-ctr",                     16, 24, 0,  0, 0, EVP_aes_192_ctr },
{ "aes256-ctr",                     16, 32, 0,  0, 0, EVP_aes_256_ctr },
{ "aes128-gcm@openssh.com",         16, 16, 12, 16, 0, EVP_aes_128_gcm },
{ "aes256-gcm@openssh.com",         16, 32, 12, 16, 0, EVP_aes_256_gcm },
{ "chacha20-poly1305@openssh.com",  8,  64, 0,  16, CFLAG_CHACHAPOLY, NULL },
```

We observed that for the `SSH2_MSG_USERAUTH_SUCCESS` packet, the sizings appear to be 28 bytes (TCP length) for the `aes*-ctr` and `chacha20-poly1305@openssh.com` ciphers, and 36 bytes (TCP length) for the `aes*-gcm@openss.com` ciphers. As seen, they mainly differ in the `auth_len`. As for why chacha20 has the same size as `aes*-ctr`, despite its `auth_len` of `16`, may have to do with the small `block_size` and thereby also small IV size, which defaults to `block_size`, if `0`.

## Authentication

Once successfully authenticated, `(52) SSH2_MSG_USERAUTH_SUCCESS` is sent to the client ([ref](https://github.com/openssh/openssh-portable/blob/2f9d2af5cb19905d87f37d1e11c9f035ac5daf3b/auth2.c#L437)).  
According to the [RFC](https://www.rfc-editor.org/rfc/rfc4252):

> When the server accepts authentication, it MUST respond with the
>   following: 
>   ```
>   byte      SSH_MSG_USERAUTH_SUCCESS
>   ```
>  `SSH_MSG_USERAUTH_SUCCESS` MUST be sent only once.  When
   `SSH_MSG_USERAUTH_SUCCESS` has been sent, any further authentication
   requests received after that SHOULD be silently ignored.

In [auth2.c](https://github.com/openssh/openssh-portable/blob/2f9d2af5cb19905d87f37d1e11c9f035ac5daf3b/auth2.c#L437), this response is sent as follows:

```c
if (authenticated == 1) {
		/* turn off userauth */
		ssh_dispatch_set(ssh, SSH2_MSG_USERAUTH_REQUEST,
		    &dispatch_protocol_ignore);
		if ((r = sshpkt_start(ssh, SSH2_MSG_USERAUTH_SUCCESS)) != 0 ||
		    (r = sshpkt_send(ssh)) != 0 ||
		    (r = ssh_packet_write_wait(ssh)) != 0)
			fatal_fr(r, "send success packet");
		/* now we can break out */
		authctxt->success = 1;
		ssh_packet_set_log_preamble(ssh, "user %s", authctxt->user);
```

It constructs the packet using type `52`, and then sends it- nothing else is added to the packet, which to me indicates that its real size is always known, and its encrypted/padded size can be inferred. This is important, as we can then have a reliable marker for a successful login, as the key offers and failed attempts prove tricky to distinguish.

The [sshpkt_start](https://github.com/openssh/openssh-portable/blob/master/packet.c#L2656) function is defined as follows:

```c
int
sshpkt_start(struct ssh *ssh, u_char type)
{
	u_char buf[6]; /* u32 packet length, u8 pad len, u8 type */

	DBG(debug("packet_start[%d]", type));
	memset(buf, 0, sizeof(buf));
	buf[sizeof(buf) - 1] = type;
	sshbuf_reset(ssh->state->outgoing_packet);
	return sshbuf_put(ssh->state->outgoing_packet, buf, sizeof(buf));
}
```

So, a packet of 6 bytes is constructed initially.  
It is then packaged via [ssh_packet_send2_wrapped](https://github.com/openssh/openssh-portable/blob/master/packet.c#L1072). The SSH2 format is "compress, mac, encrypt, enqueue".

Encrypion, MAC, and compression algorithms are set. `SSH_DIGEST_MAX_LENGTH` is `64` (`digest.h:22`).
```c
	struct session_state *state = ssh->state;
	u_char type, *cp, macbuf[SSH_DIGEST_MAX_LENGTH];
	u_char tmp, padlen, pad = 0;
	u_int authlen = 0, aadlen = 0;
	u_int len;
	struct sshenc *enc   = NULL;
	struct sshmac *mac   = NULL;
	struct sshcomp *comp = NULL;
	int r, block_size;

	if (state->newkeys[MODE_OUT] != NULL) {
		enc  = &state->newkeys[MODE_OUT]->enc;
		mac  = &state->newkeys[MODE_OUT]->mac;
		comp = &state->newkeys[MODE_OUT]->comp;
		/* disable mac for authenticated encryption */
		if ((authlen = cipher_authlen(enc->cipher)) != 0)
			mac = NULL;
	}
```

We see that MAC is disabled for authenticated encryption, which for our intents and purposes means the `gcm` ciphers and `chacha20`, where `auth_len=16`.  

Block size is then defined, as well as `aadlen`, which stands for additional authenticated data.

```c
block_size = enc ? enc->block_size : 8;
aadlen = (mac && mac->enabled && mac->etm) || authlen ? 4 : 0;
```

So, block size is taken from the cipher, and `aadlen` is set to `4` given an `authlen` or an enabled `mac`- otherwise, it's `0`.

Then, if compression is set (depends on KEX, AFAICT), the payload is compressed (not the header).

```c
	if (comp && comp->enabled) {
		len = sshbuf_len(state->outgoing_packet);
		/* skip header, compress only payload */
		if ((r = sshbuf_consume(state->outgoing_packet, 5)) != 0)
			goto out;
		sshbuf_reset(state->compression_buffer);
		if ((r = compress_buffer(ssh, state->outgoing_packet,
		    state->compression_buffer)) != 0)
			goto out;
		sshbuf_reset(state->outgoing_packet);
		if ((r = sshbuf_put(state->outgoing_packet,
		    "\0\0\0\0\0", 5)) != 0 ||
		    (r = sshbuf_putb(state->outgoing_packet,
		    state->compression_buffer)) != 0)
			goto out;
		DBG(debug("compression: raw %d compressed %zd", len,
		    sshbuf_len(state->outgoing_packet)));
	}
```

I will assume, for now, this does not apply to us, as I see `ssh_packet_enable_delayed_compress` is called once `SSH2_MSG_USERAUTH_SUCCESS` is sent and received by the client. It could be that some compression is enabled by default, but I will need to investigate KEX to verify that.

So, at this point `len` is defined as `packet_len + pad_len + payload`:

```c
/* sizeof (packet_len + pad_len + payload) */
len = sshbuf_len(state->outgoing_packet);
```
I can only assume this to be the same as what was created by `sshpkt_start` previously, so for `52` this _should_ be `6`.  

Padding is then calculated- **minimum padding is 4 bytes**.	

```c
/*
 * calc size of padding, alloc space, get random data,
 * minimum padding is 4 bytes
 */
len -= aadlen; /* packet length is not encrypted for EtM modes */
padlen = block_size - (len % block_size);
if (padlen < 4)
	padlen += block_size;
if (state->extra_pad) {
	tmp = state->extra_pad;
	state->extra_pad =
	    ROUNDUP(state->extra_pad, block_size);
	/* check if roundup overflowed */
	if (state->extra_pad < tmp)
		return SSH_ERR_INVALID_ARGUMENT;
	tmp = (len + padlen) % state->extra_pad;
	/* Check whether pad calculation below will underflow */
	if (tmp > state->extra_pad)
		return SSH_ERR_INVALID_ARGUMENT;
	pad = state->extra_pad - tmp;
	DBG(debug3_f("adding %d (len %d padlen %d extra_pad %d)",
	    pad, len, padlen, state->extra_pad));
	tmp = padlen;
	padlen += pad;
	/* Check whether padlen calculation overflowed */
	if (padlen < tmp)
		return SSH_ERR_INVALID_ARGUMENT; /* overflow */
	state->extra_pad = 0;
}
```

So, for `aes256-gcm`, for instance, we would have:

```
len = (packet_len=??? + pad_len=??? + payload=6 bytes (?)) -> 6
aadlen = 4 (because we have auth_len=16)
therefore, len -= 4 -> 2
padlen = 16 - (len % 16) -> 14

padlen > 4, so we can proceed
```

There is no extra padding for this message.  
After some more reserving and other checks and random padding, `len` is re-calculated:

```c
/* sizeof (packet_len + pad_len + payload + padding) */
len = sshbuf_len(state->outgoing_packet);
cp = sshbuf_mutable_ptr(state->outgoing_packet);
if (cp == NULL) {
	r = SSH_ERR_INTERNAL_ERROR;
	goto out;
}
/* packet_length includes payload, padding and padding length field */
POKE_U32(cp, len - 4);
cp[4] = padlen;
DBG(debug("send: len %d (includes padlen %d, aadlen %d)",
    len, padlen, aadlen));
```

So, for us:

```
len = 6 + 14 -> 20
includes padlen = 14, aadlen = 4
```

For `aes256-gcm` in this message, no MAC seems to be computed, judged from the absence of their respective debugging messages, but even if so, the packet size does not change. We also observe the length of `20` on wireshark, confirming our calculations:

```
debug1: packet_start[52] [preauth]
debug3: send packet: type 52 [preauth]
debug1: send: len 20 (includes padlen 14, aadlen 4) [preauth]
```

(Final TCP length is 36 (102 wireshark), but with these we can see the plaintext_len field, which shows 20).

Let's see if we get the same values for the other CTR and ChaCha20 ciphers:

```
aes256-ctr: blocksize=16, auth_len=0
-> aadlen=4 (auth_len is zero, but MAC is in use)
-> len=2 (6-4 for aadlen)
-> padlen=14 (from 16 - (2 % 16))
--> len=20
--> includes padlen=14, aadlen=4
--> MAC EtM 
```

> Note: There is this interesting call but as far as I can tell it only applies to compressing packets AFTER server sent `52` and AFTER client received it:
> ```c
> 	else if (type == SSH2_MSG_USERAUTH_SUCCESS && state->server_side)
>		r = ssh_packet_enable_delayed_compress(ssh);
>```

This occurs in the same wrapped function sending the packet.