#include "include.h"
#include <tchar.h>


using namespace std;

BOOL is_main_window(HWND handle)
{
	return GetWindow(handle, GW_OWNER) == (HWND)0 && IsWindowVisible(handle);
}

BOOL CALLBACK enum_windows_callback(HWND handle, LPARAM lParam)
{
	handle_data& data = *(handle_data*)lParam;
	unsigned long process_id = 0;
	GetWindowThreadProcessId(handle, &process_id);
	if (data.process_id != process_id || !is_main_window(handle)) {
		return TRUE;
	}
	data.best_handle = handle;
	return FALSE;
}


// Gets HWND of main window from process id
HWND find_main_window(unsigned long process_id)
{
	handle_data data;
	data.process_id = process_id;
	data.best_handle = 0;
	EnumWindows(enum_windows_callback, (LPARAM)&data);
	return data.best_handle;
}








#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383


// Gets registry keys under hKey
void QueryKey(HKEY hKey)
{
	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
	DWORD    cbName;                   // size of name string 
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name 
	DWORD    cchClassName = MAX_PATH;  // size of class string 
	DWORD    cSubKeys = 0;               // number of subkeys 
	DWORD    cbMaxSubKey;              // longest subkey size 
	DWORD    cchMaxClass;              // longest class string 
	DWORD    cValues;              // number of values for key 
	DWORD    cchMaxValue;          // longest value name 
	DWORD    cbMaxValueData;       // longest value data 
	DWORD    cbSecurityDescriptor; // size of security descriptor 
	FILETIME ftLastWriteTime;      // last write time 

	DWORD i, retCode;

	TCHAR  achValue[MAX_VALUE_NAME];
	DWORD cchValue = MAX_VALUE_NAME;

	// Get the class name and the value count. 
	retCode = RegQueryInfoKey(
		hKey,                    // key handle 
		achClass,                // buffer for class name 
		&cchClassName,           // size of class string 
		NULL,                    // reserved 
		&cSubKeys,               // number of subkeys 
		&cbMaxSubKey,            // longest subkey size 
		&cchMaxClass,            // longest class string 
		&cValues,                // number of values for this key 
		&cchMaxValue,            // longest value name 
		&cbMaxValueData,         // longest value data 
		&cbSecurityDescriptor,   // security descriptor 
		&ftLastWriteTime);       // last write time 

								 // Enumerate the subkeys, until RegEnumKeyEx fails.

	if (cSubKeys)
	{
		for (i = 0; i<cSubKeys; i++)
		{
			cbName = MAX_KEY_LENGTH;
			retCode = RegEnumKeyEx(hKey, i,
				achKey,
				&cbName,
				NULL,
				NULL,
				NULL,
				&ftLastWriteTime);
			if (retCode == ERROR_SUCCESS)
			{
				_tprintf(TEXT("%s\n"), achKey);

				char key[512] = { 0 };
				char data[512] = { 0 };
				int size = 512;
				HKEY hTestKey;

				sprintf(key, "%s%s", "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\", achKey);
				strcat(key, "\\");

				if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
					key,
					0,
					KEY_READ,
					&hTestKey) == ERROR_SUCCESS
					)
				{
					QueryKey(hTestKey);
				}
			}
		}
	}

	// Enumerate the key values. 

	if (cValues)
	{
		char data[512] = {0};
		int size = 512;

		for (i = 0, retCode = ERROR_SUCCESS; i<cValues; i++)
		{
			DWORD type = 0;
			cchValue = MAX_VALUE_NAME;
			achValue[0] = '\0';
			retCode = RegEnumValue(hKey, i,
				achValue,
				&cchValue,
				NULL,
				&type,
				(LPBYTE)data,
				(LPDWORD)&size);

			if (retCode == ERROR_SUCCESS && type == REG_SZ)
			{
				_tprintf(TEXT("\t%s: %s\n"), achValue, data);
			}
			else if (retCode == ERROR_SUCCESS && type == REG_DWORD)
			{
				_tprintf(TEXT("\t%s: %d\n"), achValue, *((int *)data));
			}
		}
	}
}

