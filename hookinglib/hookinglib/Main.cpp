#include "HookManager.h"
#include <process.h>

void TestHooks( void* pUseless )
{
	AllocConsole( );
	FILE *conin, *conout;
	SetConsoleTitleA( "[LOG]" );
	freopen_s( &conin, "conin$", "r", stdin );
	freopen_s( &conout, "conout$", "w", stdout );
	freopen_s( &conout, "conout$", "w", stderr );

	// do hooks and stuff
	std::vector<std::pair<std::string, DWORD_PTR>> hooks = hookManager->GetHookedFunctionsDesc( );
	printf( "Hooked functions:\n\n" );
	for ( auto elem : hooks )
	{
		printf( "[%s] At 0x%X", elem.first, elem.second );
	}

	return;
}

BOOL APIENTRY DllMain( HINSTANCE hInstance, DWORD fdwReason, LPVOID lpvReserved )
{
	if ( fdwReason == DLL_PROCESS_ATTACH )
		_beginthread( TestHooks, 0, nullptr );

	return TRUE;
}