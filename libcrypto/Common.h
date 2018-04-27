
#pragma once

#include <mutex>
#include <libdevcore/Common.h>
#include <libdevcore/FixedHash.h>
#include <libdevcore/Exceptions.h>

namespace dev
{

using Secret = SecureFixedHash<32>;

using Public = h512;

using Signature = h520;

struct SignatureStruct
{
	SignatureStruct() = default;
	SignatureStruct(Signature const& _s) { *(h520*)this = _s; }
	SignatureStruct(h256 const& _r, h256 const& _s, byte _v): r(_r), s(_s), v(_v) {}
	operator Signature() const { return *(h520 const*)this; }

	bool isValid() const noexcept;

	Public recover(h256 const& _hash) const;

	h256 r;
	h256 s;
	byte v = 0;
};

using Address = h160;

extern Address ZeroAddress;

using Addresses = h160s;

using AddressHash = std::unordered_set<h160>;

using Secrets = std::vector<Secret>;

Public toPublic(Secret const& _secret);

Address toAddress(Public const& _public);

Address toAddress(Secret const& _secret);

Address toAddress(Address const& _from, u256 const& _nonce);

void encrypt(Public const& _k, bytesConstRef _plain, bytes& o_cipher);

bool decrypt(Secret const& _k, bytesConstRef _cipher, bytes& o_plaintext);

void encryptSym(Secret const& _k, bytesConstRef _plain, bytes& o_cipher);

bool decryptSym(Secret const& _k, bytesConstRef _cipher, bytes& o_plaintext);

void encryptECIES(Public const& _k, bytesConstRef _plain, bytes& o_cipher);

void encryptECIES(Public const& _k, bytesConstRef _sharedMacData, bytesConstRef _plain, bytes& o_cipher);

bool decryptECIES(Secret const& _k, bytesConstRef _cipher, bytes& o_plaintext);

bool decryptECIES(Secret const& _k, bytesConstRef _sharedMacData, bytesConstRef _cipher, bytes& o_plaintext);

std::pair<bytes, h128> encryptSymNoAuth(SecureFixedHash<16> const& _k, bytesConstRef _plain);

bytes encryptAES128CTR(bytesConstRef _k, h128 const& _iv, bytesConstRef _plain);

bytesSec decryptAES128CTR(bytesConstRef _k, h128 const& _iv, bytesConstRef _cipher);

inline bytes encryptSymNoAuth(SecureFixedHash<16> const& _k, h128 const& _iv, bytesConstRef _plain) { return encryptAES128CTR(_k.ref(), _iv, _plain); }
inline bytes encryptSymNoAuth(SecureFixedHash<32> const& _k, h128 const& _iv, bytesConstRef _plain) { return encryptAES128CTR(_k.ref(), _iv, _plain); }

inline bytesSec decryptSymNoAuth(SecureFixedHash<16> const& _k, h128 const& _iv, bytesConstRef _cipher) { return decryptAES128CTR(_k.ref(), _iv, _cipher); }
inline bytesSec decryptSymNoAuth(SecureFixedHash<32> const& _k, h128 const& _iv, bytesConstRef _cipher) { return decryptAES128CTR(_k.ref(), _iv, _cipher); }

Public recover(Signature const& _sig, h256 const& _hash);

Signature sign(Secret const& _k, h256 const& _hash);

bool verify(Public const& _k, Signature const& _s, h256 const& _hash);

bytesSec pbkdf2(std::string const& _pass, bytes const& _salt, unsigned _iterations, unsigned _dkLen = 32);

bytesSec scrypt(std::string const& _pass, bytes const& _salt, uint64_t _n, uint32_t _r, uint32_t _p, unsigned _dkLen);

class KeyPair
{
public:
	KeyPair() = default;


	KeyPair(Secret const& _sec);

	static KeyPair create();

	static KeyPair fromEncryptedSeed(bytesConstRef _seed, std::string const& _password);

	Secret const& secret() const { return m_secret; }

	Secret const& sec() const { return m_secret; }
	Public const& pub() const { return m_public; }

	Address const& address() const { return m_address; }

	bool operator==(KeyPair const& _c) const { return m_public == _c.m_public; }
	bool operator!=(KeyPair const& _c) const { return m_public != _c.m_public; }

private:
	Secret m_secret;
	Public m_public;
	Address m_address;
};

namespace crypto
{

DEV_SIMPLE_EXCEPTION(InvalidState);

h256 kdf(Secret const& _priv, h256 const& _hash);

class Nonce
{
public:
	static Secret get() { static Nonce s; return s.next(); }

private:
	Nonce() = default;

	Secret next();

	std::mutex x_value;
	Secret m_value;
};

}

}
