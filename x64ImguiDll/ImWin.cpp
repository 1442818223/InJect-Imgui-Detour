
#include "dllmain.h"
#include "force.h"

// ȫ�ֱ���
bool mainBeginsate = TRUE;
ImGuiTabBarFlags tab_bar_flags = ImGuiTabBarFlags_None;  // ʹ�� ImGuiTabBarFlags ���ͣ������ǲ���ֵ
bool ��ѡ�� = FALSE;  // ����ֵ��ѡ�����

// ѡ��һ��������
//void ѡ��һ() {
//	// ����һ����ǩҳ�Tab Item��
//	if (ImGui::BeginTabItem("Tab ѡ��һ"))  // ʹ�� ImGui::BeginTabItem ���� ImGui::BeginTabBar
//	{
//		// ������д�������ݣ��������ֻ��߰�ť
//		ImGui::Text(u8"����ѡ��һ������");
//
//		// ���� Tab Item
//		ImGui::EndTabItem();  // ������� Tab Item
//	}
//}

// �����ڼ��غ���
void LoadMyWin() {
	// IMGUI ��ܵĹ̶���ʼ������
	ImGui_ImplDX9_NewFrame();
	ImGui_ImplWin32_NewFrame();
	ImGui::NewFrame();

	// ���ô���λ�úʹ�С
	ImGui::SetNextWindowPos(ImVec2(50, 50), ImGuiCond_FirstUseEver);
	ImGui::SetNextWindowSize(ImVec2(350, 450));

	// ����һ������
	ImGui::Begin(u8"�˻���г", &mainBeginsate);//������ָʾ�����Ƿ�Ӧ������ʾ

	// ����һ����ǩ����Tab Bar������ǩ���ı�ǩΪ"tab1"����ָ�� tab_bar_flags
	if (ImGui::BeginTabBar("tab1", tab_bar_flags))
	{
		// ��ʾһЩ�ı�����
		ImGui::Text(u8"��ӭʹ��IMGUI����");
		//ImGui::SameLine();  // ͬһ����ʾ
		//ImGui::Text(u8"��ӭʹ��IMGUI����2");
		//ImGui::Text(u8"��ӭʹ��IMGUI����3");

		 // ��⸴ѡ��״̬�Ƿ����仯
		if (ImGui::Checkbox(u8"��͸����", &��ѡ��)) {
			// ���ݸ�ѡ��״̬���ò�ͬ�ĺ���
			if (��ѡ��) {
				Show();  // ��ѡ��ѡ��ʱ���õĺ���
			}
			else {
				NoShow();  // ��ѡ��δѡ��ʱ���õĺ���
			}
		}

		// ����һ����ť
		if (ImGui::Button(u8"��ȫж���˳�")) {
			// ��ť�����ִ�еĲ���
			// ����������д�߼��������ʼ����Ϸ��

			unLoad();
		}


		// ���� Tab Bar
		ImGui::EndTabBar();  // ������� Tab Bar
	}

	// ��������
	ImGui::End();

	// IMGUI ��ܵĹ̶���������
	ImGui::EndFrame();
	ImGui::Render();
	ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
}