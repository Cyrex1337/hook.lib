#include "HookManager.h"

// change constructor if using vftable hooking
std::unique_ptr<HookManager> hookManager( new HookManager( ) );

DWORD_PTR HookManager::DetourJMP( DWORD_PTR At, DWORD_PTR To, size_t Length )
{
	byte* codeCave = ( byte* )VirtualAlloc( NULL, Length + 0x5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	memcpy( codeCave, ( const void* )At, Length );

	DWORD Old;
	VirtualProtect( ( LPVOID )At, Length, PAGE_EXECUTE_READWRITE, &Old );

	*( byte* )At = 0xE9;
	*( DWORD_PTR* )( At + 0x1 ) = ( DWORD_PTR )( codeCave - ( At + 0x5 ) );

	for ( size_t i( 0x5 ); i < Length; ++i )
		*( byte* )( At + i ) = 0x90;

	VirtualProtect( ( LPVOID )At, Length, Old, &Old );

	codeCave += Length;
	*( byte* )codeCave = 0xE9;
	*( DWORD_PTR* )( codeCave + 0x1 ) = ( DWORD_PTR )( ( At + Length ) - ( DWORD_PTR )( codeCave + 0x5 ) );

	return ( DWORD_PTR )( codeCave - Length );
}

DWORD_PTR HookManager::DetourCALL( DWORD_PTR At, DWORD_PTR To, size_t Length )
{
	byte* codeCave = ( byte* )VirtualAlloc( NULL, Length + 0x5, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	memcpy( codeCave, ( const void* )At, Length );

	DWORD Old;
	VirtualProtect( ( LPVOID )At, Length, PAGE_EXECUTE_READWRITE, &Old );

	*( byte* )At = 0xE8;
	*( DWORD_PTR* )( At + 0x1 ) = ( DWORD_PTR )( codeCave - ( At + 0x5 ) );

	for ( size_t i( 0x5 ); i < Length; ++i )
		*( byte* )( At + i ) = 0x90;

	VirtualProtect( ( LPVOID )At, Length, Old, &Old );

	codeCave += Length;
	*( byte* )codeCave = 0xE8;
	*( DWORD_PTR* )( codeCave + 0x1 ) = ( DWORD_PTR )( ( At + Length ) - ( DWORD_PTR )( codeCave + 0x5 ) );

	return ( DWORD_PTR )( codeCave - Length );
}

size_t HookManager::VftFunctions( )
{
	size_t i = 0;
	DWORD_PTR* table = ( DWORD_PTR* )pTable;
	DWORD_PTR curFunc = table[i];

	while ( curFunc && !IsBadReadPtr( ( const void* )curFunc, 4 ) )
	{
		++i;
		curFunc = table[i];
	}

	return i;
}

DWORD_PTR HookManager::RedirectFuncPtr( size_t Index, DWORD_PTR Proxy )
{
	if ( !pObject || !pTable )
		return NULL;

	DWORD_PTR* tableArray = ( DWORD_PTR* )pTable;
	DWORD_PTR orig = tableArray[Index];
	DWORD Old;

	// just to be safe lol
	VirtualProtect( ( LPVOID )&tableArray[Index], 4, PAGE_EXECUTE_READWRITE, &Old );
	tableArray[Index] = Proxy;
	VirtualProtect( ( LPVOID )&tableArray[Index], 4, Old, &Old );

	++functionCounter;
	char buf[200];
	sprintf( buf, "%s [%i]", "Vftable Hook", functionCounter );
	hookedFunctions.push_back( std::make_pair( buf, orig ) );

	return orig;
}

DWORD_PTR HookManager::SwapVftable( size_t Index, DWORD_PTR Proxy )
{
	size_t nVfuncs = VftFunctions( );
	DWORD_PTR* ppNewTable = ( DWORD_PTR* )VirtualAlloc( NULL, sizeof( DWORD_PTR ) * nVfuncs, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
	if ( !ppNewTable )
		return NULL;
	memcpy( ppNewTable, ( const void* )pTable, sizeof( DWORD_PTR ) * nVfuncs );

	DWORD_PTR* oldTable = ( DWORD_PTR* )pTable;
	DWORD_PTR orig = oldTable[Index];

	ppNewTable[Index] = Proxy;

	*( DWORD_PTR** )pObject = ppNewTable;

	++functionCounter;
	char buf[200];
	sprintf( buf, "%s [%i]", "Vftable Swap", functionCounter );
	hookedFunctions.push_back( std::make_pair( buf, orig ) );

	return orig;
}

DWORD_PTR HookManager::HookIAT( const char* ExportDll, const char* ImportDll, const char* Function, DWORD_PTR Proxy )
{
	HMODULE hImportDll = GetModuleHandleA( ImportDll );
	if ( !hImportDll ) return NULL;

	IMAGE_DOS_HEADER* pIDH = ( IMAGE_DOS_HEADER* )hImportDll;
	IMAGE_NT_HEADERS* pINH = ( IMAGE_NT_HEADERS* )( ( DWORD )hImportDll + pIDH->e_lfanew );
	IMAGE_IMPORT_DESCRIPTOR* pIID = ( IMAGE_IMPORT_DESCRIPTOR* )( ( DWORD )hImportDll + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress );
	while ( pIID->Characteristics )
	{
		char* curDllName = ( char* )( ( DWORD )hImportDll + pIID->Name );
		if ( !_stricmp( curDllName, ExportDll ) ) break;
		++pIID;
	}

	IMAGE_THUNK_DATA* OrigFirstThunk = ( IMAGE_THUNK_DATA* )( ( DWORD )hImportDll + pIID->OriginalFirstThunk );
	IMAGE_THUNK_DATA* FirstThunk = ( IMAGE_THUNK_DATA* )( ( DWORD )hImportDll + pIID->FirstThunk );

	while ( OrigFirstThunk->u1.AddressOfData )
	{
		IMAGE_IMPORT_BY_NAME* pImportByName = ( IMAGE_IMPORT_BY_NAME* )( ( DWORD )hImportDll + OrigFirstThunk->u1.AddressOfData );
		char* curFunctionName = ( char* )( ( DWORD )hImportDll + pImportByName->Name );
		if ( !_stricmp( curFunctionName, Function ) ) break;
		++OrigFirstThunk;
		++FirstThunk;
	}

	DWORD origImport = FirstThunk->u1.Function;

	DWORD Old;
	VirtualProtect( &FirstThunk->u1.Function, 4, PAGE_EXECUTE_READWRITE, &Old );
	FirstThunk->u1.Function = Proxy;
	VirtualProtect( &FirstThunk->u1.Function, 4, Old, &Old );

	++functionCounter;
	char buf[200];
	sprintf( buf, "%s [%i]", "IAT Hook", functionCounter );
	hookedFunctions.push_back( std::make_pair( buf, origImport ) );

	return origImport;
}

DWORD_PTR HookManager::HookEAT( const char* ExportDll, const char* Function, DWORD_PTR Proxy )
{
	DWORD ModuleBase = (DWORD)GetModuleHandleA( ExportDll );
	IMAGE_DOS_HEADER* pIDH = ( IMAGE_DOS_HEADER* )ModuleBase;
	IMAGE_NT_HEADERS* pINH = ( IMAGE_NT_HEADERS* )( ModuleBase + pIDH->e_lfanew );
	IMAGE_EXPORT_DIRECTORY* pIED = ( IMAGE_EXPORT_DIRECTORY* )( ModuleBase + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress );

	DWORD_PTR* FunctionTable = ( DWORD_PTR* )( ModuleBase + pIED->AddressOfFunctions );
	DWORD_PTR* NameOrdinalTable = ( DWORD_PTR* )( ModuleBase + pIED->AddressOfNameOrdinals );
	DWORD_PTR* NameTable = ( DWORD_PTR* )( ModuleBase + pIED->AddressOfNames );

	size_t idx = 0;
	for ( ; idx < pIED->NumberOfNames; ++idx )
		if ( !_stricmp( Function, ( const char* )NameTable[idx] ) )
			break;

	if ( idx > pIED->NumberOfNames )
		return NULL;

	DWORD_PTR origRVA = FunctionTable[NameOrdinalTable[idx]];

	DWORD Old;
	VirtualProtect( &FunctionTable[NameOrdinalTable[idx]], sizeof( DWORD_PTR ), PAGE_EXECUTE_READWRITE, &Old );
	FunctionTable[NameOrdinalTable[idx]] = Proxy - ModuleBase;
	VirtualProtect( &FunctionTable[NameOrdinalTable[idx]], sizeof( DWORD_PTR ), Old, &Old );

	++functionCounter;
	char buf[200];
	sprintf( buf, "%s [%i]", "EAT Hook", functionCounter );
	hookedFunctions.push_back( std::make_pair( buf, origRVA ) );

	return origRVA;
}