
#include "dllmain.h"

extern ULONG64 MouDle1 = 0;

#ifdef _WIN64
#define GWL_WNDPROC GWLP_WNDPROC
#endif

typedef HRESULT(WINAPI* Reset_t)(LPDIRECT3DDEVICE9, D3DPRESENT_PARAMETERS*); //19
typedef long(__stdcall* EndScene_t)(LPDIRECT3DDEVICE9);                      //42
typedef LRESULT(__stdcall* WndProc_t)(const HWND, UINT, WPARAM, LPARAM);//IMGUI窗口消息处理函数



D3DPRESENT_PARAMETERS g_present;
IDirect3D9* g_Direct3D9 = NULL;
IDirect3DDevice9* g_pd3dDevice = NULL;//关键hook虚表函数处 hook下面两个  
// STDMETHOD(Reset)(THIS_ D3DPRESENT_PARAMETERS* pPresentationParameters) PURE;   com形式的定义方法
// STDMETHOD(EndScene)(THIS) PURE;                                                PURE: 这是一个宏，通常用于表示该方法是纯虚函数

HWND g_hwnd = NULL;

Reset_t oReset;
EndScene_t oEndScene;
WndProc_t oWndProc;////IMGUI窗口消息处理函数指针对象

//64位改为LONG_PTR  ,其他地方完全一样
//DWORD* dDeviceVT = NULL;
PCHAR* dDeviceVT = NULL;


//重画
HRESULT __stdcall hkReset(IDirect3DDevice9* pd3dDevice, D3DPRESENT_PARAMETERS* pPresentationParameters)
{
	//printf("我进来\n");
	Helpers::UnHookFunction((PVOID*)(&oReset), hkReset);

	ImGui_ImplDX9_InvalidateDeviceObjects();
	HRESULT tmpReset = pd3dDevice->Reset(pPresentationParameters);
	ImGui_ImplDX9_CreateDeviceObjects();

	Helpers::HookFunction((PVOID*)(&oReset), hkReset);
	return tmpReset;
}



void MineImGuiInit(IDirect3DDevice9* pd3dDevice) {
	// 检查IMGUT版本
	IMGUI_CHECKVERSION();
	// 创建IMGUI上下文
	ImGui::CreateContext();
	ImGuiIO& io = ImGui::GetIO();
	//关闭imgui配置文件的显示
	io.ConfigFlags = ImGuiConfigFlags_NoMouseCursorChange;
	io.WantSaveIniSettings = false;
	io.IniFilename = NULL;

	//设置ImGui风格
	//ImGuiStyle & style = ImGui :: GetStyle();
	// ImGui :: StyleColorsDark();
	ImGui::StyleColorsClassic();
	//ImGui:: StyleColorsLight();
	//LoadMyStype();


	//设置字体---为了显示中文
	ImFontConfig f_cfg;
	f_cfg.FontDataOwnedByAtlas = false;
	ImFont* font = io.Fonts->AddFontFromFileTTF("c:\\Windows\\Fonts\\msyh.ttc", 25.0f, nullptr, io.Fonts->GetGlyphRangesChineseFull());
	//IM_ASSERT(font != nullptr);                     //字体                                                //能显示中文

	ImGui_ImplWin32_Init(g_hwnd);
	ImGui_ImplDX9_Init(pd3dDevice);
}
// 窗口消息处理，获取窗操作消息转嫁给IMGUI
extern /*IMGUI_IMPL_API*/ LRESULT  ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT _stdcall hkwndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wParam, lParam)) return true;
	return CallWindowProc(oWndProc, hwnd, msg, wParam, lParam);
}
HRESULT __stdcall hkEndScene(IDirect3DDevice9* pd3dDevice)
{
	//恢复
	Helpers::UnHookFunction((PVOID*)(&oEndScene), hkEndScene);

	//IMGUT初始化
	static bool firstcall = TRUE;
	if (firstcall)
	{
		firstcall = !firstcall;
		MineImGuiInit(pd3dDevice);

		//设置窗口过程函数
		oWndProc = (WNDPROC)SetWindowLongPtr(g_hwnd, GWL_WNDPROC, (LONG_PTR)hkwndProc);

	}


	HRESULT result = pd3dDevice->EndScene();//必须执行原来的函数


	LoadMyWin();//加载IMGUI窗口

	//HOOK
	Helpers::HookFunction((PVOID*)(&oEndScene), hkEndScene);
	return result; //返回原函数的返回值
}



void InitD3d() {

	//	AllocConsole();
	//#pragma warning(disable: 4996)
	//	freopen("CON", "w", stdout);
	//#pragma warning(default: 4996)
	//	SetConsoleTitleA("调试窗口");


		//获取游戏目标窗口句柄
	//g_hwnd = FindWindowA("Direct3DwindowClass", NULL);
	
	do 
	{
		g_hwnd = FindWindowA("CrossFire", "穿越火线");
	} while (g_hwnd == NULL);

	
	//创建D3D设备对象
	g_Direct3D9 = Direct3DCreate9(D3D_SDK_VERSION);

	//初始化参数结构体
	memset(&g_present, 0, sizeof(g_present));
	g_present.Windowed = TRUE;
	g_present.SwapEffect = D3DSWAPEFFECT_DISCARD;
	g_present.BackBufferFormat = D3DFMT_UNKNOWN;
	g_present.EnableAutoDepthStencil = TRUE;
	g_present.AutoDepthStencilFormat = D3DFMT_D16;

	//创建D3D9设备标识
	HRESULT result = g_Direct3D9->CreateDevice(
		D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL,
		g_hwnd, D3DCREATE_SOFTWARE_VERTEXPROCESSING,
		&g_present, &g_pd3dDevice
	);


	 MouDle1 = (unsigned __int64)GetModuleHandle(L"crossfire.exe");


	//开始hook对应的D3D9函数
	dDeviceVT = (PCHAR*)*(PCHAR*)g_pd3dDevice; //拿到 IDirect3DDevice9虚表首地址
	oReset = (Reset_t)dDeviceVT[16]; //拿到第16个函数地址,保存起来以便于恢复
	oEndScene = (EndScene_t)dDeviceVT[42];//拿到第42个函数地址

	Helpers::HookFunction((PVOID*)(&oReset), hkReset);
	Helpers::HookFunction((PVOID*)(&oEndScene), hkEndScene);
}
void unLoad()
{
	// 释放 ImGui 相关资源
	ImGui_ImplDX9_Shutdown();
	ImGui_ImplWin32_Shutdown();
	ImGui::DestroyContext();

	// 卸载钩子
	Helpers::UnHookFunction((PVOID*)(&oReset), hkReset);
	Helpers::UnHookFunction((PVOID*)(&oEndScene), hkEndScene);

	// 释放 Direct3D 设备和 Direct3D 对象
	if (g_pd3dDevice != NULL)
	{
		g_pd3dDevice->Release();
		g_pd3dDevice = NULL;
	}

	if (g_Direct3D9 != NULL)
	{
		g_Direct3D9->Release();
		g_Direct3D9 = NULL;
	}

	// 恢复窗口过程函数
	if (g_hwnd != NULL && oWndProc != NULL)
	{
		SetWindowLongPtr(g_hwnd, GWL_WNDPROC, (LONG_PTR)oWndProc);
		oWndProc = NULL;
	}

	exit(-1);
}
// 当使用预编译的头时，需要使用此源文件，编译才能成功。
BOOL WINAPI DllMain(
	HINSTANCE hinstDLL,  // DLL模块的句柄
	DWORD fdwReason,     // 调用的情况
	LPVOID lpReserved)  // reserved
{
	// 在不同的情况下都会调用 DllMain 函数，分别处理
	switch (fdwReason)
	{
		// 加载Dll
	case DLL_PROCESS_ATTACH:     
		DisableThreadLibraryCalls(hinstDLL);
		//CloseHandle(CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InitD3d, NULL, 0, NULL));
		//CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InitD3d, NULL, 0, NULL);
		
		InitD3d();

		break;
		// 新建线程
	case DLL_THREAD_ATTACH:
		break;
		// 线程退出
	case DLL_THREAD_DETACH:
		break;
		// 释放Dll
	case DLL_PROCESS_DETACH:
		unLoad();
		break;
	}
	return TRUE;
}