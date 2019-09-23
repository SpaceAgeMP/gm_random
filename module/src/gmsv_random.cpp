
#include "GarrysMod/Lua/Interface.h"
#include <math.h>
#include <malloc.h>

using namespace GarrysMod::Lua;

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <random>
#include <time.h>
size_t getrandom(void *buf, size_t buflen, unsigned int flags)
{
	unsigned char *bufc = (unsigned char*)buf;
	for (size_t i = 0; i < buflen; i++)
	{
		bufc[i] = (rand() & 0xFF);
	}
	return buflen;
}
#else
#include <sys/random.h>
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

	if (LUA->IsType(1, Type::NUMBER))
	{
		returnFloat = false;
		if (LUA->IsType(2, Type::NUMBER))
		{
			min = (int)LUA->GetNumber(1);
			max = (int)LUA->GetNumber(2);
			if (LUA->IsType(3, Type::BOOL))
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
		getrandom(&s, sizeof(RandInts), NULL);
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
	getrandom(&wholeNum, sizeof(int), NULL);
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
	if (LUA->IsType(2, Type::BOOL))
	{
		allowAll = LUA->GetBool(2);
	}
	else if (LUA->IsType(2, Type::STRING))
	{
		letters = LUA->GetString(2);
		lettercount = strlen(letters);
	}

	char *out = (char*)malloc(len + 1);
	getrandom(out, len, NULL);

	if (!allowAll)
	{
		for (size_t i = 0; i < len; i++)
		{
			out[i] = letters[out[i] % lettercount];
		}
	}

	out[len] = 0;
	LUA->PushString(out, len);

	return 1;
}

GMOD_MODULE_OPEN()
{
#ifdef _WIN32
	srand((unsigned int)time(NULL));
#endif

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
