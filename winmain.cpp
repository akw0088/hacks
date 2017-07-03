#include "include.h"
#include "resource.h"
#include <TlHelp32.h>


#include <GL/GL.h>
#include "glext.h"


PFNGLACTIVETEXTUREARBPROC glActiveTextureARB;

// FrameBuffer (FBO) gen, bin and texturebind
PFNGLGENFRAMEBUFFERSEXTPROC glGenFramebuffersEXT;
PFNGLBINDFRAMEBUFFEREXTPROC glBindFramebufferEXT;
PFNGLFRAMEBUFFERTEXTURE2DEXTPROC glFramebufferTexture2DEXT;
PFNGLCHECKFRAMEBUFFERSTATUSEXTPROC glCheckFramebufferStatusEXT;

// Shader functions
PFNGLCREATEPROGRAMOBJECTARBPROC  glCreateProgramObjectARB;
PFNGLUSEPROGRAMOBJECTARBPROC     glUseProgramObjectARB;
PFNGLCREATESHADEROBJECTARBPROC   glCreateShaderObjectARB;
PFNGLSHADERSOURCEARBPROC         glShaderSourceARB;
PFNGLCOMPILESHADERARBPROC        glCompileShaderARB;
PFNGLGETOBJECTPARAMETERIVARBPROC glGetObjectParameterivARB;
PFNGLATTACHOBJECTARBPROC         glAttachObjectARB;
PFNGLLINKPROGRAMARBPROC          glLinkProgramARB;
PFNGLGETUNIFORMLOCATIONARBPROC   glGetUniformLocationARB;
PFNGLUNIFORM1IARBPROC            glUniform1iARB;
PFNGLGETINFOLOGARBPROC           glGetInfoLogARB;


using namespace std;

BOOL CALLBACK DialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
typedef HMODULE(WINAPI *LoadLibrary_t)(LPCSTR);
LoadLibrary_t orig_LoadLibrary;
extern BYTE oldBytes[SIZE];



// Returns vtable for object (vtable is at begining of class, think of as an integer array)
DWORD* GetVtableAddress(void* pObject)
{
	// The first 4 bytes of the object is a pointer to the vtable:
	return (DWORD*)*((DWORD*)pObject);
}

// Redefines vtable of an object to insert a hook at given index
void HookFunction(DWORD* pVtable, void* pHookProc, void* pOldProc, int iIndex)
{
	// Enable writing to the vtable at address we aquired
	DWORD lpflOldProtect;
	VirtualProtect((void*)&pVtable[iIndex], sizeof(DWORD), PAGE_READWRITE, &lpflOldProtect);

	// Store old address
	if (pOldProc)
	{
		*(DWORD*)pOldProc = pVtable[iIndex];
	}

	// Overwrite original address
	pVtable[iIndex] = (DWORD)pHookProc;

	// Restore protection
	VirtualProtect(pVtable, sizeof(DWORD), lpflOldProtect, &lpflOldProtect);
}


// Old bytes at function pointer address
BYTE oldBytes[SIZE] = { 0 };

// New jump instruction
BYTE JMP[SIZE] = { 0 };

// Prevent memory protection exceptions
DWORD oldProtect, myProtect = PAGE_EXECUTE_READWRITE;


// Search for loading of target dll
HMODULE WINAPI LoadLibrary_Hook(LPCSTR lpFileName)
{
	printf("Hooked LoadLibrary loading %s\n", lpFileName);

	VirtualProtect((LPVOID)pOrigMBAddress, SIZE, myProtect, NULL);     // assign read write protection
	memcpy(pOrigMBAddress, oldBytes, SIZE);                            // remove hook so we can call original function without recursion

	HMODULE retValue = LoadLibraryA(lpFileName);       // Call original

	memcpy(pOrigMBAddress, JMP, SIZE);                                 // Readd hook for next time
	VirtualProtect((LPVOID)pOrigMBAddress, SIZE, oldProtect, NULL);    // reset protection
	return retValue;                                                   // return original return value
}


// Places JMP to hook function at function pointer of target function
void BeginRedirect(LPVOID newFunction)
{
	BYTE tempJMP[SIZE] = { 0xE9, 0x90, 0x90, 0x90, 0x90, 0xC3 };       // 0xE9 = JMP 0x90 = NOP 0xC3 = RET
	memcpy(JMP, tempJMP, SIZE);                                        // store jmp instruction to JMP
	DWORD JMPSize = ((DWORD)newFunction - (DWORD)pOrigMBAddress - 5);  // calculate jump distance
	VirtualProtect((LPVOID)pOrigMBAddress, SIZE,                       // assign read write protection
		PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(oldBytes, pOrigMBAddress, SIZE);                            // make backup
	memcpy(&JMP[1], &JMPSize, 4);				           // fill the nop's with the jump distance (JMP,distance(4bytes),RET)
	memcpy(pOrigMBAddress, JMP, SIZE);                                 // set jump instruction at the beginning of the original function
	VirtualProtect((LPVOID)pOrigMBAddress, SIZE, oldProtect, NULL);    // reset protection
}

// Finds address of LoadLibrary and inserts a jmp instruction infront of it for hooking calls
void AddHook()
{
	printf("Hooking LoadLibrary\r\n");
	pOrigMBAddress = (pMessageBoxA)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
	if (pOrigMBAddress != NULL)
		BeginRedirect(LoadLibrary_Hook);

}

// Creates a console window for printf output
void CreateConsole(void)
{
	if (AllocConsole())
	{
		freopen("CONOUT$", "w", stdout);
		SetConsoleTitle("Debug Console");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
	}
}

// Gets a list of running processes
bool getCurrentProcesses()
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	HANDLE shot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (shot == INVALID_HANDLE_VALUE)
	{
		return false;
	}
	if (!Process32First(shot, &pe32))
	{
		CloseHandle(shot);
		return false;
	}
	do
	{
		printf("%s\t %u\t %d\t %d\t %u\n",
			pe32.szExeFile,
			pe32.th32ParentProcessID,
			pe32.cntThreads,
			pe32.pcPriClassBase,
			pe32.th32ProcessID
		);
	} while (Process32Next(shot, &pe32));
	CloseHandle(shot);
	return true;
}

// DLL injection code (can use external tool, but will likely do the same thing)
HMODULE InjectDLL(DWORD ProcessID, char* dllName)
{
	HANDLE Proc;
	HANDLE Thread;
	char buf[50] = { 0 };
	LPVOID RemoteString, LoadLibAddy;
	HMODULE hModule = NULL;
	DWORD dwOut;

	if (!ProcessID)
		return false;

	Proc = OpenProcess(PROCESS_ALL_ACCESS, 0, ProcessID);

	if (!Proc)
	{
		sprintf_s(buf, "OpenProcess() failed: %d", GetLastError());
		MessageBoxA(NULL, buf, "Loader", NULL);
		return false;
	}

	LoadLibAddy = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
	if (!LoadLibAddy)
	{
		return false;
	}


	RemoteString = (LPVOID)VirtualAllocEx(Proc, NULL, strlen(dllName), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!RemoteString)
	{
		return false;
	}

	if (!WriteProcessMemory(Proc, (LPVOID)RemoteString, dllName, strlen(dllName), NULL))
	{
		return false;
	}

	Thread = CreateRemoteThread(Proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, NULL, NULL);
	if (!Thread)
	{
		return false;
	}
	else
	{
		while (GetExitCodeThread(Thread, &dwOut))
		{
			if (dwOut != STILL_ACTIVE)
			{
				hModule = (HMODULE)dwOut;
				break;
			}
		}
	}

	CloseHandle(Thread);
	CloseHandle(Proc);

	return hModule;
}


#define DIALOG
#ifdef DIALOG
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR szCmdLine, int iCmdShow)
{
	HWND hDlg;
	MSG msg;

	hDlg = CreateDialogParam(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), 0, DialogProc, 0);
	ShowWindow(hDlg, iCmdShow);

	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return 0;
}
#endif

#ifdef INJECT
#include <windows.h>
#include <iostream>
//#include "inject.h"

const char* EXE_NAME = "Island11.exe"; // target executable
const char* DLL_NAME = "d3d11.dll"; // dll to inject

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	char path[MAX_PATH];
	char exename[MAX_PATH];
	char dllname[MAX_PATH];

	// aquire full path to exe:
	GetModuleFileNameA(0, path, MAX_PATH);

	// find the position of the last backslash and delete whatever follows
	// (eg C:\Games\loader.exe becomes C:\Games\)
	int pos = 0;
	for (int k = 0; k < strlen(path); k++) {
		if (path[k] == '\\') {
			pos = k;
		}
	}
	path[pos + 1] = 0; // null-terminate it for strcat

					   // build path to target
	strcpy_s(exename, path);
	strcat_s(exename, EXE_NAME);

	// build path to dll
	strcpy_s(dllname, path);
	strcat_s(dllname, DLL_NAME);

	// launch program:
	STARTUPINFOA siStartupInfo;
	PROCESS_INFORMATION piProcessInfo;
	memset(&siStartupInfo, 0, sizeof(siStartupInfo));
	memset(&piProcessInfo, 0, sizeof(piProcessInfo));
	siStartupInfo.cb = sizeof(siStartupInfo);

	if (!CreateProcessA(NULL,
		exename, 0, 0, false,
		CREATE_SUSPENDED, 0, 0,
		&siStartupInfo, &piProcessInfo)) {
		MessageBoxA(NULL, exename, "Error", MB_OK);
	}

	// get the process id for injection
	DWORD pId = piProcessInfo.dwProcessId;

	// Inject the dll
	if (!InjectDLL(pId, dllname)) {
		MessageBoxA(NULL, "Injection failed", "Error", MB_OK);
	}

	ResumeThread(piProcessInfo.hThread);

	return 0;
}
#endif

void QueryKey(HKEY hKey);


// Get list of installed applications on windows box from registry
void ListInstalled()
{
	HKEY hTestKey;

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		TEXT("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"),
		0,
		KEY_READ,
		&hTestKey) == ERROR_SUCCESS
		)
	{
		QueryKey(hTestKey);
	}

	RegCloseKey(hTestKey);
}


// Dialog process function
BOOL CALLBACK DialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
	static HWND edit1;
	static HWND edit2;
	static HWND edit3;
	static HWND edit4;

	switch (message)
	{
	case WM_INITDIALOG:
		CreateConsole();
		AddHook();
		ListInstalled();
		edit1 = GetDlgItem(hDlg, IDC_EDIT1);
		edit2 = GetDlgItem(hDlg, IDC_EDIT2);
		edit3 = GetDlgItem(hDlg, IDC_EDIT3);
		edit4 = GetDlgItem(hDlg, IDC_EDIT4);
		return TRUE;

	case WM_COMMAND:
		switch (LOWORD(wParam))
		{
		case IDC_BUTTON1:
			if (HIWORD(wParam) == BN_CLICKED)
			{
				HINSTANCE dll = LoadLibrary("opengl32.dll");
				if (dll != NULL)
				{
					glCreateProgramObjectARB = (PFNGLCREATEPROGRAMOBJECTARBPROC)GetProcAddress(dll, "glCreateProgramObject");
				}
			}
			break;
		case IDC_BUTTON2:
//			if (HIWORD(wParam) == BN_CLICKED)
			break;
		case IDC_BUTTON3:
//			if (HIWORD(wParam) == BN_CLICKED)
			break;
		case IDC_BUTTON4:
//			if (HIWORD(wParam) == BN_CLICKED)
			break;
		case IDOK:
		case IDCANCEL:
			EndDialog(hDlg, 0);
			DestroyWindow(hDlg);
			break;
		}
		return 0;
	case WM_CLOSE:
		memcpy(pOrigMBAddress, oldBytes, SIZE);
		EndDialog(hDlg, 0);
		DestroyWindow(hDlg);
		return 0;
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProc(hDlg, message, wParam, lParam);
}



