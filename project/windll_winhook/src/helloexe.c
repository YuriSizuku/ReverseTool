#include <windows.h>
#ifndef _UNICODE
#define _UNICODE
#endif

HWND hwnd;
LRESULT CALLBACK WndProc(HWND hwnd, UINT Msg, WPARAM wParam, LPARAM lParam);

int CALLBACK wWinMain(HINSTANCE hInstance, 
    HINSTANCE hPrevInstance, wchar_t * lpCmdLine, int nCmdShow)
{
  	MSG Msg;
    WNDCLASSEXW  WndClsEx = {0};
    WndClsEx.cbSize        = sizeof (WNDCLASSEXW);
    WndClsEx.style         = CS_HREDRAW | CS_VREDRAW;
    WndClsEx.lpfnWndProc   = WndProc;
    WndClsEx.hInstance     = hInstance;
    WndClsEx.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    WndClsEx.lpszClassName = L"HelloWorldClass";
    WndClsEx.hIconSm       = LoadIcon(hInstance, IDI_APPLICATION);
    RegisterClassExW(&WndClsEx);
    hwnd = CreateWindowExW(WS_EX_OVERLAPPEDWINDOW,
                L"HelloWorldClass", (LPCWSTR)L"Hello World",
                WS_OVERLAPPEDWINDOW, 100, 120, 400, 200,
                NULL, NULL, hInstance, NULL);
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);
    while(GetMessage(&Msg, NULL, 0, 0))
    {
        TranslateMessage(&Msg);
        DispatchMessage(&Msg);
    }
	return 0;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
    switch(Msg)
    {
    case WM_DESTROY:
    {
        PostQuitMessage(WM_QUIT);
        break;
    }
	case WM_PAINT:
    {
        PAINTSTRUCT ps;
        HDC         hdc;
        RECT        rc;
        hdc = BeginPaint(hwnd, &ps);
        GetClientRect(hwnd, &rc);
        SetTextColor(hdc, 0);
        SetBkMode(hdc, TRANSPARENT);
        DrawTextW(hdc, L"HELLO WORLD", -1, &rc, DT_CENTER|DT_SINGLELINE|DT_VCENTER);
        EndPaint(hwnd, &ps);
        break;
	};
    default:
        return DefWindowProc(hwnd, Msg, wParam, lParam);
    }
    return 0;
}