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


//******************************************************  //������һ��Ҫ�ֱ���� �ֱ��� ��ѹ64,32���� �ֱ����
#include"imgui/detours.h" //�����ҵ�detour�����include�ļ������� 
#include"imgui/detver.h"
//******************************************************


#include"ImWin.h"
#include"Helpers.h"



#pragma comment(lib,"d3d9.lib") 
#pragma comment(lib,"detours.lib")  //x64���Ӳ��ϾͰ����ֱ�����64λ�µ�detours.lib�ϵ�IM��

void unLoad();