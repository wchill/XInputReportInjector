// Adapted from https://github.com/r57zone/XInputInjectDLL
#include "pch.h"
#include "minhook.h"
#include <cstdio>
#include <iostream>
#include <chrono>

#pragma comment(lib, "libMinHook.x64.lib")


#define XINPUT_GAMEPAD_DPAD_UP          0x0001
#define XINPUT_GAMEPAD_DPAD_DOWN        0x0002
#define XINPUT_GAMEPAD_DPAD_LEFT        0x0004
#define XINPUT_GAMEPAD_DPAD_RIGHT       0x0008
#define XINPUT_GAMEPAD_START            0x0010
#define XINPUT_GAMEPAD_BACK             0x0020
#define XINPUT_GAMEPAD_LEFT_THUMB       0x0040
#define XINPUT_GAMEPAD_RIGHT_THUMB      0x0080
#define XINPUT_GAMEPAD_LEFT_SHOULDER    0x0100
#define XINPUT_GAMEPAD_RIGHT_SHOULDER   0x0200
#define XINPUT_GAMEPAD_A                0x1000
#define XINPUT_GAMEPAD_B                0x2000
#define XINPUT_GAMEPAD_X                0x4000
#define XINPUT_GAMEPAD_Y				0x8000

#define BATTERY_TYPE_DISCONNECTED		0x00

#define XUSER_MAX_COUNT                 4
#define XUSER_INDEX_ANY					0x000000FF


typedef struct _XINPUT_GAMEPAD
{
	WORD                                wButtons;
	BYTE                                bLeftTrigger;
	BYTE                                bRightTrigger;
	SHORT                               sThumbLX;
	SHORT                               sThumbLY;
	SHORT                               sThumbRX;
	SHORT                               sThumbRY;
} XINPUT_GAMEPAD, * PXINPUT_GAMEPAD;

typedef struct _XINPUT_STATE
{
	DWORD                               dwPacketNumber;
	XINPUT_GAMEPAD                      Gamepad;
} XINPUT_STATE, * PXINPUT_STATE;


typedef DWORD(WINAPI* XINPUTGETSTATE)(DWORD, XINPUT_STATE*);

// Pointer for calling original
static XINPUTGETSTATE hookedXInputGetState = nullptr;
static std::chrono::system_clock::time_point start;
static int reportCount;

template <typename T>
inline MH_STATUS MH_CreateHookApiEx(LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, T** ppOriginal)
{
	MH_STATUS status = MH_CreateHookApi(pszModule, pszProcName, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
	if (status == MH_OK) {
		std::wcout << L"Hooking " << pszModule << L" " << pszProcName << L" OK" << std::endl;
	}
	else {
		std::wcout << L"Hooking " << pszModule << L" " << pszProcName << L" " << status << std::endl;
	}
	return status;
}

DWORD WINAPI detourXInputGetState(DWORD dwUserIndex, XINPUT_STATE* pState)
{
	DWORD toReturn = hookedXInputGetState(dwUserIndex, pState);

	auto end = std::chrono::system_clock::now();
	std::chrono::duration<double> elapsed_seconds = end - start;
	reportCount++;

	if (elapsed_seconds.count() >= 1.0) {
		double avg = reportCount / elapsed_seconds.count();
		reportCount = 0;
		start = end;
		std::cout << "Report count: " << avg << std::endl;
	}

	return toReturn;
}

// https://stackoverflow.com/a/57241985/1502893
void CreateConsole()
{
	if (!AllocConsole()) {
		// Add some error handling here.
		// You can call GetLastError() to get more info about the error.
		return;
	}

	// std::cout, std::clog, std::cerr, std::cin
	FILE* fDummy;
	freopen_s(&fDummy, "CONOUT$", "w", stdout);
	freopen_s(&fDummy, "CONOUT$", "w", stderr);
	freopen_s(&fDummy, "CONIN$", "r", stdin);
	std::cout.clear();
	std::clog.clear();
	std::cerr.clear();
	std::cin.clear();

	// std::wcout, std::wclog, std::wcerr, std::wcin
	HANDLE hConOut = CreateFile(L"CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hConIn = CreateFile(L"CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	SetStdHandle(STD_OUTPUT_HANDLE, hConOut);
	SetStdHandle(STD_ERROR_HANDLE, hConOut);
	SetStdHandle(STD_INPUT_HANDLE, hConIn);
	std::wcout.clear();
	std::wclog.clear();
	std::wcerr.clear();
	std::wcin.clear();
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateConsole();
		start = std::chrono::system_clock::now();
		reportCount = 0;
		std::cout << "Attached" << std::endl;

		if (MH_Initialize() == MH_OK)
			std::cout << "Initialized OK" << std::endl;

		//1.0
		MH_CreateHookApiEx(L"XINPUT9_1_0", "XInputGetStateEx", &detourXInputGetState, &hookedXInputGetState);

		//1_1
		if (hookedXInputGetState == nullptr)
			MH_CreateHookApiEx(L"XINPUT_1_1", "XInputGetState", &detourXInputGetState, &hookedXInputGetState);

		//1_2
		if (hookedXInputGetState == nullptr)
			MH_CreateHookApiEx(L"XINPUT_1_2", "XInputGetState", &detourXInputGetState, &hookedXInputGetState);

		//1_3
		if (hookedXInputGetState == nullptr)
			MH_CreateHookApiEx(L"XINPUT1_3", "XInputGetState", &detourXInputGetState, &hookedXInputGetState);

		//1_4
		if (hookedXInputGetState == nullptr)
			MH_CreateHookApiEx(L"XINPUT1_4", "XInputGetState", &detourXInputGetState, &hookedXInputGetState);

		if (MH_EnableHook(MH_ALL_HOOKS) == MH_OK)
			std::cout << "XInput Hooked" << std::endl;

		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

