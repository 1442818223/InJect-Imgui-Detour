#pragma once
#include <windows.h>
#include<d3d9.h>

#include"imgui/imconfig.h"
#include"imgui/imgui.h"
#include"imgui/imgui_impl_dx9.h"
#include"imgui/imgui_impl_win32.h"
#include"imgui/imgui_internal.h"
#include"imgui/imstb_rectpack.h"
#include"imgui/imstb_textedit.h"
#include"imgui/imstb_truetype.h"


//******************************************************  //这玩意一定要分别编译 分别用 解压64,32两份 分别编译
#include"imgui/detours.h" //必须找到detour里面的include文件拉进来 
#include"imgui/detver.h"
//******************************************************


#include"ImWin.h"
#include"Helpers.h"



#pragma comment(lib,"d3d9.lib") 
#pragma comment(lib,"detours.lib")  //x64链接不上就把他分别编译的64位下的detours.lib拖到IM下

void unLoad();