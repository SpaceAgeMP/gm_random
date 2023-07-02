
#include "GarrysMod/Lua/Interface.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

using namespace GarrysMod::Lua;

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS

#include <winternl.h>
#include <ntstatus.h>
#include <winerror.h>

#include <Bcrypt.h>

static size_t mkrandom(void *buf, size_t buflen)
{
	NTSTATUS status = BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)buflen, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
	if (!NT_SUCCESS(status)) {
		return 0;
	}
	return buflen;
}
#elif defined(__APPLE__)
#include <Security/Security.h>
#include <Security/SecRandom.h>
static size_t mkrandom(void *buf, size_t buflen)
{
	int status = SecRandomCopyBytes(kSecRandomDefault, buflen, buf);
	if (status != errSecSuccess) {
		return 0;
	}
	return buflen;
}
#else
#include <sys/random.h>
#define mkrandom(buf, buflen) getrandom(buf, buflen, 0)
#endif

struct RandInts {
	unsigned short int a;
	unsigned short int b;
	unsigned short int c;
};

LUA_FUNCTION(MakeSecureRandomNumber)
{
	bool returnFloat = true;
	int min = 0;
	int max = 1;

	if (LUA->IsType(1, Type::Number))
	{
		returnFloat = false;
		if (LUA->IsType(2, Type::Number))
		{
			min = (int)LUA->GetNumber(1);
			max = (int)LUA->GetNumber(2);
			if (LUA->IsType(3, Type::Bool))
			{
				returnFloat = LUA->GetBool(3);
			}
		}
		else
		{
			min = 1;
			max = (int)LUA->GetNumber(1);
		}
	}

	if (returnFloat)
	{
		struct RandInts s;
		size_t res = mkrandom(&s, sizeof(RandInts));
		if (res != sizeof(RandInts))
		{
			LUA->ThrowError("mkrandom() failed");
			return 1;
		}

		double num = ldexp(s.a, -48) + ldexp(s.b, -32) + ldexp(s.c, -16);

		if (min == 0)
		{
			if (max != 1)
			{
				num *= max;
			}
		}
		else
		{
			num = (num * (max - min)) + min;
		}

		LUA->PushNumber(num);
		return 1;
	}

	int wholeNum;
	size_t res = mkrandom(&wholeNum, sizeof(int));
	if (res != sizeof(int))
	{
		LUA->ThrowError("mkrandom() failed");
		return 1;
	}

	if (wholeNum < 0)
	{
		wholeNum *= -1;
	}

	max++;
	if (min == 0)
	{
		wholeNum %= max;
	}
	else
	{
		wholeNum = ((wholeNum - min) % (max - min)) + min;
	}
	LUA->PushNumber(wholeNum);
	return 1;
}

const char *B64_LETTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

LUA_FUNCTION(MakeSecureRandomString)
{
	size_t len = (size_t)LUA->CheckNumber(1);

	bool allowAll = false;
	const char *letters = B64_LETTERS;
	size_t lettercount = 64;
	if (LUA->IsType(2, Type::Bool))
	{
		allowAll = LUA->GetBool(2);
	}
	else if (LUA->IsType(2, Type::String))
	{
		letters = LUA->GetString(2);
		lettercount = strlen(letters);
	}

	char *out = (char*)malloc(len + 1);
	if (out == NULL)
	{
		LUA->ThrowError("malloc() failed");
		return 1;
	}

	size_t res = mkrandom(out, len);
	if (res != len)
	{
		LUA->ThrowError("mkrandom() failed");
		return 1;
	}

	if (!allowAll)
	{
		for (size_t i = 0; i < len; i++)
		{
			out[i] = letters[out[i] % lettercount];
		}
	}

	out[len] = 0;
	LUA->PushString(out, (unsigned int)len);

	return 1;
}

GMOD_MODULE_OPEN()
{
	LUA->PushSpecial(SPECIAL_GLOB);
	LUA->PushString("SecureRandomNumber");
	LUA->PushCFunction(MakeSecureRandomNumber);
	LUA->SetTable(-3);

	LUA->PushSpecial(SPECIAL_GLOB);
	LUA->PushString("SecureRandomString");
	LUA->PushCFunction(MakeSecureRandomString);
	LUA->SetTable(-3);

	return 0;
}

GMOD_MODULE_CLOSE()
{
	return 0;
}
