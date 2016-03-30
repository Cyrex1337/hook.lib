#pragma once

#include <Windows.h>
#include <memory>
#include <vector>
#include <string>
#include <unordered_map>
#include <map>

class HookManager
{
private:
	// Vftable hooks
	size_t functionCounter = 0;
	std::vector<std::pair<std::string, DWORD_PTR>> hookedFunctions;
	bool HooksInstalled( ) const { return hookedFunctions.size( ) > 0; }
	DWORD_PTR pObject;
	DWORD_PTR pTable;

public:
	HookManager( ) = default;
	HookManager( DWORD_PTR object ) : pObject( object )
	{
		pTable = *( DWORD_PTR* )pObject;
	}
	HookManager( DWORD_PTR object, DWORD_PTR table ) : pObject( object ), pTable( table ) { }

	HookManager( const HookManager& manager ) = delete;
	HookManager( HookManager&& manager ) = delete;

public:
	DWORD_PTR DetourJMP( DWORD_PTR At, DWORD_PTR To, size_t Length );
	DWORD_PTR DetourCALL( DWORD_PTR At, DWORD_PTR To, size_t Length );

public:
	bool IsValidTable( ) const
	{
		if ( !pObject || IsBadReadPtr( ( const void* )pObject, 4 ) || !pTable || IsBadReadPtr( ( const void* )pTable, 4 ) )
		{
			MessageBox( NULL, L"Please use the constructor overloads to specify the object and table.\nObject or Table ptr are not valid pointers", L"Error", 0 );
			return false;
		}

		return true;
	}

	std::vector<std::pair<std::string, DWORD_PTR>> GetHookedFunctionsDesc( ) const { return hookedFunctions; }

	DWORD_PTR SwapVftable( size_t Index, DWORD_PTR Proxy );
	DWORD_PTR RedirectFuncPtr( size_t Index, DWORD_PTR Proxy );

private:
	size_t VftFunctions( );

public:
	DWORD_PTR HookIAT( const char* ExportDll, const char* ImportDll, const char* Function, DWORD_PTR Proxy );
	DWORD_PTR HookEAT( const char* ExportDll, const char* Function, DWORD_PTR Proxy );
};

extern std::unique_ptr<HookManager> hookManager;