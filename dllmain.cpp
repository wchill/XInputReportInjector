// Adapted from https://github.com/r57zone/XInputInjectDLL
#include "pch.h"
#include "minhook.h"
#include <cstdio>
#include <iostream>
#include <chrono>
#include <Psapi.h>
#include <mutex>
#include <queue>

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


#define RESPONSE_HOST_ENABLED			0x00
#define RESPONSE_ACK					0x01
#define RESPONSE_NACK					0x02
#define RESPONSE_USER_OVERRIDE			0x03
#define RESPONSE_UNKNOWN_ERROR			0xFF

#define REQUEST_UPDATE_REPORT			0x00
#define REQUEST_UPDATE_REPORT_FOR_MSEC	0x01
#define REQUEST_STOP					0xFF

#define HID_BUTTON_Y					0x0001
#define HID_BUTTON_B					0x0002
#define HID_BUTTON_A					0x0004
#define HID_BUTTON_X					0x0008
#define HID_BUTTON_L					0x0010
#define HID_BUTTON_R					0x0020
#define HID_BUTTON_ZL					0x0040
#define HID_BUTTON_ZR					0x0080
#define HID_BUTTON_MINUS				0x0100
#define HID_BUTTON_PLUS					0x0200
#define HID_BUTTON_L3					0x0400
#define HID_BUTTON_R3					0x0800

#define HID_DPAD_CENTER					0x08
#define HID_DPAD_UP						0x00
#define HID_DPAD_UP_RIGHT				0x01
#define HID_DPAD_RIGHT					0x02
#define HID_DPAD_DOWN_RIGHT				0x03
#define HID_DPAD_DOWN					0x04
#define HID_DPAD_DOWN_LEFT				0x05
#define HID_DPAD_LEFT					0x06
#define HID_DPAD_UP_LEFT				0x07

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
static WORD lastButtons = 0;
static BOOL enableGamepadInput = false;

static std::atomic<int> dwPacketNum;
static std::mutex inputMutex;
static std::pair<XINPUT_STATE, int> currentReport;
static std::queue<std::pair<XINPUT_STATE, int>> reportQueue;

template <typename T>
inline MH_STATUS MH_CreateHookApiEx(LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, T** ppOriginal)
{
	MH_STATUS status = MH_CreateHookApi(pszModule, pszProcName, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
	if (status == MH_OK) {
		std::wcout << L"Hooking " << pszModule << L" " << pszProcName << L" OK" << std::endl;
	} else {
		std::wcout << L"Hooking " << pszModule << L" " << pszProcName << L" " << status << std::endl;
	}
	return status;
}

DWORD WINAPI detourXInputGetState(DWORD dwUserIndex, XINPUT_STATE* pState)
{
	if (dwUserIndex != 0) {
		return ERROR_DEVICE_NOT_CONNECTED;
	}

	XINPUT_STATE actualState;
	ZeroMemory(pState, sizeof(XINPUT_STATE));
	DWORD toReturn = hookedXInputGetState(0, &actualState);

	if (toReturn == ERROR_SUCCESS) {
		if (lastButtons != actualState.Gamepad.wButtons) {
			if (actualState.Gamepad.wButtons == (XINPUT_GAMEPAD_START | XINPUT_GAMEPAD_BACK)) {
				enableGamepadInput = ~enableGamepadInput;

				std::cout << "Gamepad: ";
				if (enableGamepadInput) {
					std::cout << "enabled";
				}
				else {
					std::cout << "disabled";
				}
				std::cout << std::endl;
			}
			lastButtons = actualState.Gamepad.wButtons;
		}
	}
	else {
		if (enableGamepadInput) {
			enableGamepadInput = false;
			ZeroMemory(&actualState, sizeof(XINPUT_STATE));
			std::cout << "Gamepad unplugged, disabling gamepad override" << std::endl;
		}
	}

	if (enableGamepadInput) {
		pState->Gamepad = actualState.Gamepad;
		
		// Don't pass through the toggle to the game
		if (actualState.Gamepad.wButtons == (XINPUT_GAMEPAD_START | XINPUT_GAMEPAD_BACK)) {
			pState->Gamepad.wButtons = 0;
		}
	}
	else {
		// TODO: Report fake inputs
	}

	pState->dwPacketNumber = dwPacketNum.fetch_add(1);
	return ERROR_SUCCESS;
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

static bool endsWith(const std::wstring& str, const std::wstring& suffix)
{
	return str.size() >= suffix.size() && 0 == str.compare(str.size() - suffix.size(), suffix.size(), suffix);
}

void CheckForSpecialK()
{
	// TODO: Maybe we can just apply Special K's patches ourselves
	HANDLE hProcess = GetCurrentProcess();
	HMODULE lphModule[1024];
	DWORD cbNeeded;
	if (EnumProcessModulesEx(hProcess, lphModule, 1024, &cbNeeded, LIST_MODULES_ALL) == 0) {
		MessageBox(0, L"Error during EnumProcessModulesEx", L"Error during EnumProcessModulesEx", MB_OK);
		exit(1);
	}

	DWORD totalCount = cbNeeded / sizeof(HMODULE);
	WCHAR* filename = new WCHAR[32768];
	BOOL specialKFound = false;
	std::wstring specialKDllName(L"kaldaien_api64.dll");
	for (DWORD i = 0; i < totalCount; i++) {
		if (GetModuleFileNameExW(hProcess, lphModule[i], filename, 32768) != 0) {
			std::wcout << L"Module loaded: " << filename << std::endl;
			std::wstring filenameStr(filename);
			if (endsWith(filenameStr, specialKDllName)) {
				specialKFound = true;
				break;
			}
		}
	}
	delete[] filename;

	if (!specialKFound) {
		MessageBox(0, L"Special K not found", L"Special K must be injected", MB_OK);
		exit(1);
	}
}

void AddReportToQueue(XINPUT_STATE report, int msec) {
	const std::lock_guard<std::mutex> inputLock(inputMutex);
	reportQueue.emplace(report, msec);
}

DWORD LittleEndianBytesToUInt32(char* b) {
	return (b[3] << 24) | (b[2] << 16) | (b[1] << 8) | (b[0]);
}

WORD LittleEndianBytesToUInt16(char* b) {
	return (b[1] << 8) | (b[0]);
}

SHORT ScaleHidAxisToXInput(BYTE val) {
	DWORD range = val * 256;
	return (SHORT)(range - 32768);
}

void ReadXInputStateFromHidReportBytes(XINPUT_STATE *state, char* b) {
	WORD hidButtons = LittleEndianBytesToUInt16(&b[0]);
	BYTE hidDpad = b[2];
	BYTE hidLX = b[3];
	BYTE hidLY = b[4];
	BYTE hidRX = b[5];
	BYTE hidRY = b[6];

	state->Gamepad.bLeftTrigger = 0;
	state->Gamepad.bRightTrigger = 0;
	state->Gamepad.sThumbLX = 0;
	state->Gamepad.sThumbLY = 0;
	state->Gamepad.sThumbRX = 0;
	state->Gamepad.sThumbRY = 0;
	state->Gamepad.wButtons = 0;

	if (hidButtons & HID_BUTTON_Y) {
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_X;
	}
	if (hidButtons & HID_BUTTON_X) {
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_Y;
	}
	if (hidButtons & HID_BUTTON_A) {
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_B;
	}
	if (hidButtons & HID_BUTTON_B) {
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_A;
	}
	if (hidButtons & HID_BUTTON_L) {
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_LEFT_SHOULDER;
	}
	if (hidButtons & HID_BUTTON_R) {
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_RIGHT_SHOULDER;
	}
	if (hidButtons & HID_BUTTON_ZL) {
		state->Gamepad.bLeftTrigger = 255;
	}
	if (hidButtons & HID_BUTTON_ZR) {
		state->Gamepad.bRightTrigger = 255;
	}
	if (hidButtons & HID_BUTTON_PLUS) {
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_START;
	}
	if (hidButtons & HID_BUTTON_MINUS) {
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_BACK;
	}
	if (hidButtons & HID_BUTTON_L3) {
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_LEFT_THUMB;
	}
	if (hidButtons & HID_BUTTON_R3) {
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_RIGHT_THUMB;
	}

	switch (hidDpad) {
	case HID_DPAD_CENTER:
		break;
	case HID_DPAD_UP:
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_DPAD_UP;
		break;
	case HID_DPAD_DOWN:
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_DPAD_DOWN;
		break;
	case HID_DPAD_LEFT:
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_DPAD_LEFT;
		break;
	case HID_DPAD_RIGHT:
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_DPAD_RIGHT;
		break;
	case HID_DPAD_UP_LEFT:
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_DPAD_UP | XINPUT_GAMEPAD_DPAD_LEFT;
		break;
	case HID_DPAD_UP_RIGHT:
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_DPAD_UP | XINPUT_GAMEPAD_DPAD_RIGHT;
		break;
	case HID_DPAD_DOWN_LEFT:
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_DPAD_DOWN | XINPUT_GAMEPAD_DPAD_LEFT;
		break;
	case HID_DPAD_DOWN_RIGHT:
		state->Gamepad.wButtons |= XINPUT_GAMEPAD_DPAD_DOWN | XINPUT_GAMEPAD_DPAD_RIGHT;
		break;
	}

	state->Gamepad.sThumbLX = ScaleHidAxisToXInput(hidLX);
	state->Gamepad.sThumbLY = ScaleHidAxisToXInput(hidLY);
	state->Gamepad.sThumbRX = ScaleHidAxisToXInput(hidRX);
	state->Gamepad.sThumbRY = ScaleHidAxisToXInput(hidRY);
}

void ListenOnNamedPipe() {
	// https://stackoverflow.com/a/26561999/1502893
	char buffer[1024];

	HANDLE hPipe = CreateNamedPipe(TEXT(R"(\\.\pipe\Pipe)"),
		PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
		1,
		1024 * 16,
		1024 * 16,
		NMPWAIT_USE_DEFAULT_WAIT,
		NULL);
	while (hPipe != INVALID_HANDLE_VALUE)
	{
		if (ConnectNamedPipe(hPipe, NULL) != FALSE)   // wait for someone to connect to the pipe
		{
			DWORD dwWritten;
			BYTE response = 0x00;	// HOST_ENABLED
			WriteFile(hPipe, &response, 1, &dwWritten, NULL);

			DWORD dwRead;
			while (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &dwRead, NULL) != FALSE)
			{
				BYTE command = buffer[0];
				XINPUT_STATE state;

				switch (command) {
				case REQUEST_UPDATE_REPORT:
					ReadXInputStateFromHidReportBytes(&state, &buffer[1]);
					AddReportToQueue(state, -1);
					response = RESPONSE_ACK;
					WriteFile(hPipe, &response, 1, &dwWritten, NULL);
					break;
				case REQUEST_UPDATE_REPORT_FOR_MSEC:
					ReadXInputStateFromHidReportBytes(&state, &buffer[5]);
					AddReportToQueue(state, LittleEndianBytesToUInt32(&buffer[1]));
					response = RESPONSE_ACK;
					WriteFile(hPipe, &response, 1, &dwWritten, NULL);
					break;
				case REQUEST_STOP:
					std::cout << "Stop requested" << std::endl;
					DisconnectNamedPipe(hPipe);
					CloseHandle(hPipe);
					return;
				default:
					std::cout << "Unknown command: " << (int)command << std::endl;
				}
			}
		}

		DisconnectNamedPipe(hPipe);
	}
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(nullptr, 0x0, [](LPVOID)->DWORD
		{
			CreateConsole();
			CheckForSpecialK();

			std::cout << "Attached" << std::endl;

			if (MH_Initialize() == MH_OK)
				std::cout << "Initialized OK" << std::endl;
			
			MH_CreateHookApiEx(L"XINPUT1_4", "XInputGetState", &detourXInputGetState, &hookedXInputGetState);
			if (hookedXInputGetState == nullptr) {
				std::cout << "Failed to hook xinput1_4.dll!" << std::endl;
				return 1;
			}

			if (MH_EnableHook(MH_ALL_HOOKS) == MH_OK)
				std::cout << "XInput Hooked" << std::endl;

			ListenOnNamedPipe();
			return 0;
		}, nullptr, 0x0, nullptr);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

