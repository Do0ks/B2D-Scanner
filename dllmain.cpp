#include "pch.h"
#include <windows.h>
#include <vector>
#include <string>
#include <unordered_set>
#include <queue>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <algorithm>
using namespace std;

#pragma comment(lib, "User32.lib")

static const DWORD_PTR MAX_OFFSET = 0x1000;  // Adjust for the maximum offset to scan.
static const DWORD_PTR MAX_SUBOFFSET = 0x1000;  // Adjust for the maximum sub-offset to scan.
static const DWORD_PTR OFFSET_STEP = sizeof(DWORD_PTR);
static const int LOG_FREQUENCY = 1;

#define CONSOLE_MAX_CHARS 300000

static vector<DWORD_PTR> g_positionalOffsets;

HINSTANCE g_hInst = NULL;
HWND g_hWnd = NULL;
HWND g_editBase = NULL;
HWND g_editDynamic = NULL;
HWND g_editMaxDepth = NULL;
HWND g_btnScan = NULL;
HWND g_btnStop = NULL;
HWND g_groupPosOffsets = NULL;
HWND g_listOffsets = NULL;
HWND g_editOffsetEntry = NULL;
HWND g_btnAddOffset = NULL;
HWND g_btnRemoveOffset = NULL;
HWND g_editResults = NULL;
HWND g_editConsole = NULL;
HANDLE g_scanThread = NULL;
bool   g_stopRequested = false;
bool   g_isScanning = false;

#define WM_APPEND_CONSOLE (WM_USER + 1)

HWND g_staticBase = NULL;
HWND g_staticDynamic = NULL;
HWND g_staticMaxDepth = NULL;

WNDPROC g_oldEditOffsetProc = NULL;

//---------------------------------------------------------------------
// Helper functions for hex filtering
//---------------------------------------------------------------------

// Returns the most-significant hex digit (as an uppercase char) of addr.
char GetHighHexDigit(DWORD_PTR addr) {
    char hexDigits[] = "0123456789ABCDEF";
    if (addr == 0)
        return '0';
    char digit = '0';
    while (addr > 0) {
        digit = hexDigits[addr % 16];
        addr /= 16;
    }
    return digit;
}

// Returns the number of hex digits in address (ignores leading zeros)
int GetHexDigitCount(DWORD_PTR addr) {
    int count = 0;
    if (addr == 0) return 1;
    while (addr > 0) {
        count++;
        addr /= 16;
    }
    return count;
}

// Checks if address most-significant hex digit is one of the allowed ones.
bool IsAllowedAddress(DWORD_PTR addr, const vector<char>& allowedHighDigits) {
    char digit = GetHighHexDigit(addr);
    for (char allowed : allowedHighDigits) {
        if (allowed == digit)
            return true;
    }
    return false;
}

LRESULT CALLBACK EditOffsetProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    if (message == WM_KEYDOWN && wParam == VK_RETURN) {
        HWND hParent = GetParent(hWnd);
        SendMessageA(hParent, WM_COMMAND, MAKELPARAM(103, BN_CLICKED), (LPARAM)g_btnAddOffset);
        return 0;
    }
    return CallWindowProc(g_oldEditOffsetProc, hWnd, message, wParam, lParam);
}

struct BFSNode {
    DWORD_PTR currentPtr;
    vector<DWORD_PTR> usedOffsets;
    int depthUsed;
};

struct ScanParams {
    DWORD_PTR baseAddr;
    DWORD_PTR dynamicAddr;
    int maxDepth;
};

bool SafeReadPtr(DWORD_PTR addr, DWORD_PTR* outValue) {
    __try {
        *outValue = *(DWORD_PTR*)addr;
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

void AppendConsoleAsync(const char* text) {
    char* textCopy = _strdup(text);
    PostMessageA(g_hWnd, WM_APPEND_CONSOLE, 0, (LPARAM)textCopy);
}

string PtrToHexStr(DWORD_PTR ptr) {
    char buf[32];
    sprintf_s(buf, "0x%p", (void*)ptr);
    return string(buf);
}

string FormatChain(DWORD_PTR base, DWORD_PTR target, const vector<DWORD_PTR>& offsets) {
    if (offsets.empty()) {
        return "No pointer chain found.\r\n";
    }
    ostringstream oss;
    oss << "Pointer Chain:\r\n" << PtrToHexStr(base);

    DWORD_PTR current = base;
    size_t n = offsets.size();
    for (size_t i = 0; i < n; i++) {
        DWORD_PTR off = offsets[i];
        oss << " + " << PtrToHexStr(off);

        if (i == n - 2) {
            DWORD_PTR val = 0;
            SafeReadPtr(current + off, &val);
            current = val;
            oss << "\r\n-> " << PtrToHexStr(current);
            DWORD_PTR subOff = offsets[i + 1];
            oss << " + " << PtrToHexStr(subOff);
            current = target;
            oss << "\r\n-> " << PtrToHexStr(current);
            break;
        }
        else {
            DWORD_PTR val = 0;
            SafeReadPtr(current + off, &val);
            current = val;
            oss << "\r\n-> " << PtrToHexStr(current);
        }
    }
    if (current != target) {
        oss << "\r\n-> " << PtrToHexStr(target);
    }
    return oss.str();
}

DWORD WINAPI ScanThreadProc(LPVOID lpParam) {
    ScanParams* sp = (ScanParams*)lpParam;
    DWORD_PTR baseAddr = sp->baseAddr;
    DWORD_PTR dynamicAddr = sp->dynamicAddr;
    int maxDepth = sp->maxDepth;
    delete sp;

    // Build allowed high-digit list from base and dynamic addresses.
    vector<char> allowedHighDigits;
    char baseHigh = GetHighHexDigit(baseAddr);
    allowedHighDigits.push_back(baseHigh);
    char dynHigh = GetHighHexDigit(dynamicAddr);
    if (find(allowedHighDigits.begin(), allowedHighDigits.end(), dynHigh) == allowedHighDigits.end())
        allowedHighDigits.push_back(dynHigh);

    // Determine the expected hex digit count.
    int expectedLength = max(GetHexDigitCount(baseAddr), GetHexDigitCount(dynamicAddr));

    g_stopRequested = false;
    g_isScanning = true;

    AppendConsoleAsync("Scan started...\r\n");

    queue<BFSNode> q;
    unordered_set<DWORD_PTR> visited;
    visited.insert(baseAddr);

    BFSNode start;
    start.currentPtr = baseAddr;
    start.depthUsed = 0;
    q.push(start);

    bool found = false;
    vector<DWORD_PTR> foundOffsets;

    while (!q.empty() && !g_stopRequested) {
        BFSNode node = q.front();
        q.pop();

        {
            char buf[128];
            sprintf_s(buf, "Scanning Address: %p at depth: %d\r\n",
                (void*)node.currentPtr, node.depthUsed);
            AppendConsoleAsync(buf);
            Sleep(70);
        }

        // If reached the dynamic address directly.
        if (node.currentPtr == dynamicAddr) {
            found = true;
            foundOffsets = node.usedOffsets;
            break;
        }
        if (node.depthUsed >= maxDepth)
            continue;

        // Process using a positional offset if available.
        if (node.depthUsed < (int)g_positionalOffsets.size()) {
            DWORD_PTR off = g_positionalOffsets[node.depthUsed];
            DWORD_PTR val = 0;
            if (SafeReadPtr(node.currentPtr + off, &val)) {
                // Check for an exact match.
                if (val == dynamicAddr) {
                    found = true;
                    vector<DWORD_PTR> chain = node.usedOffsets;
                    chain.push_back(off);
                    foundOffsets = chain;
                }
                else {
                    // Check for a sub-offset: dynamicAddr == val + diff.
                    if (val != 0 && dynamicAddr > val) {
                        DWORD_PTR diff = dynamicAddr - val;
                        if (diff <= MAX_SUBOFFSET) {
                            BFSNode newNode = node;
                            newNode.usedOffsets.push_back(off);
                            newNode.usedOffsets.push_back(diff);
                            foundOffsets = newNode.usedOffsets;
                            found = true;
                        }
                    }
                }
                // If not found and the pointer is valid to follow, enqueue it.
                if (!found &&
                    IsAllowedAddress(val, allowedHighDigits) &&
                    (GetHexDigitCount(val) == expectedLength) &&
                    !visited.count(val))
                {
                    visited.insert(val);
                    BFSNode newNode;
                    newNode.currentPtr = val;
                    newNode.depthUsed = node.depthUsed + 1;
                    newNode.usedOffsets = node.usedOffsets;
                    newNode.usedOffsets.push_back(off);
                    q.push(newNode);
                }
            }
        }
        else {
            // Otherwise, scan through all offsets.
            for (DWORD_PTR off = 0; off <= MAX_OFFSET; off += OFFSET_STEP) {
                if (g_stopRequested)
                    break;
                DWORD_PTR val = 0;
                if (SafeReadPtr(node.currentPtr + off, &val)) {
                    // Check for an exact match.
                    if (val == dynamicAddr) {
                        found = true;
                        vector<DWORD_PTR> chain = node.usedOffsets;
                        chain.push_back(off);
                        foundOffsets = chain;
                        break;
                    }
                    // Check for a sub-offset match.
                    if (val != 0 && dynamicAddr > val) {
                        DWORD_PTR diff = dynamicAddr - val;
                        if (diff <= MAX_SUBOFFSET) {
                            BFSNode newNode = node;
                            newNode.usedOffsets.push_back(off);
                            newNode.usedOffsets.push_back(diff);
                            foundOffsets = newNode.usedOffsets;
                            found = true;
                            break; 
                        }
                    }
                    // Enqueue this pointer if it passes checks.
                    if (IsAllowedAddress(val, allowedHighDigits) &&
                        (GetHexDigitCount(val) == expectedLength) &&
                        !visited.count(val))
                    {
                        visited.insert(val);
                        BFSNode newNode;
                        newNode.currentPtr = val;
                        newNode.depthUsed = node.depthUsed + 1;
                        newNode.usedOffsets = node.usedOffsets;
                        newNode.usedOffsets.push_back(off);
                        q.push(newNode);
                    }
                }
            }
        }
        if (found)
            break; 
    }

    if (!g_stopRequested) {
        if (found) {
            string chainStr = FormatChain(baseAddr, dynamicAddr, foundOffsets);
            SetWindowTextA(g_editResults, chainStr.c_str());
            AppendConsoleAsync("Scan finished.\r\n");
        }
        else {
            SetWindowTextA(g_editResults, "No pointer chain found.\r\n");
            AppendConsoleAsync("Scan finished.\r\n");
        }
    }
    else {
        AppendConsoleAsync("Scan stopped by user.\r\n");
    }

    g_isScanning = false;
    return 0;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE: {
        g_staticBase = CreateWindowA("STATIC", "Base Address:", WS_VISIBLE | WS_CHILD,
            10, 10, 130, 20, hWnd, NULL, g_hInst, NULL);
        g_editBase = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL,
            150, 10, 150, 20, hWnd, NULL, g_hInst, NULL);

        g_staticDynamic = CreateWindowA("STATIC", "Dynamic Address:", WS_VISIBLE | WS_CHILD,
            10, 40, 140, 20, hWnd, NULL, g_hInst, NULL);
        g_editDynamic = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL,
            150, 40, 150, 20, hWnd, NULL, g_hInst, NULL);

        g_staticMaxDepth = CreateWindowA("STATIC", "Max Depth:", WS_VISIBLE | WS_CHILD,
            10, 70, 80, 20, hWnd, NULL, g_hInst, NULL);
        g_editMaxDepth = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "3",
            WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL,
            150, 70, 50, 20, hWnd, NULL, g_hInst, NULL);

        g_groupPosOffsets = CreateWindowA("BUTTON", "Positional Offsets",
            WS_VISIBLE | WS_CHILD | BS_GROUPBOX,
            320, 5, 250, 140,
            hWnd, NULL, g_hInst, NULL);

        g_listOffsets = CreateWindowExA(WS_EX_CLIENTEDGE, "LISTBOX", "",
            WS_VISIBLE | WS_CHILD | WS_VSCROLL | LBS_NOTIFY,
            330, 25, 230, 90,
            hWnd, (HMENU)101, g_hInst, NULL);

        g_editOffsetEntry = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL,
            330, 118, 140, 20,
            hWnd, (HMENU)102, g_hInst, NULL);
        g_oldEditOffsetProc = (WNDPROC)SetWindowLongPtr(g_editOffsetEntry, GWLP_WNDPROC, (LONG_PTR)EditOffsetProc);

        g_btnAddOffset = CreateWindowA("BUTTON", "Add",
            WS_VISIBLE | WS_CHILD,
            475, 118, 40, 20,
            hWnd, (HMENU)103, g_hInst, NULL);

        g_btnRemoveOffset = CreateWindowA("BUTTON", "Del",
            WS_VISIBLE | WS_CHILD,
            520, 118, 40, 20,
            hWnd, (HMENU)104, g_hInst, NULL);

        g_btnScan = CreateWindowA("BUTTON", "Scan",
            WS_VISIBLE | WS_CHILD,
            10, 100, 80, 30,
            hWnd, (HMENU)1, g_hInst, NULL);
        g_btnStop = CreateWindowA("BUTTON", "Stop",
            WS_VISIBLE | WS_CHILD,
            100, 100, 80, 30,
            hWnd, (HMENU)2, g_hInst, NULL);

        CreateWindowA("STATIC", "Results:", WS_VISIBLE | WS_CHILD,
            10, 150, 60, 20, hWnd, NULL, g_hInst, NULL);
        g_editResults = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_VISIBLE | WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            10, 170, 560, 140,
            hWnd, NULL, g_hInst, NULL);

        CreateWindowA("STATIC", "Output:", WS_VISIBLE | WS_CHILD,
            10, 320, 60, 20, hWnd, NULL, g_hInst, NULL);
        g_editConsole = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "",
            WS_VISIBLE | WS_CHILD | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            10, 340, 560, 200,
            hWnd, NULL, g_hInst, NULL);
        SendMessageA(g_editConsole, EM_SETLIMITTEXT, (WPARAM)0x7FFFFFFE, 0);

        return 0;
    }
    case WM_COMMAND: {
        switch (LOWORD(wParam)) {
        case 1: {
            if (!g_isScanning) {
                SetWindowTextA(g_editResults, "");
                SetWindowTextA(g_editConsole, "");
                g_stopRequested = false;

                char bufBase[64], bufDyn[64], bufDepth[16];
                GetWindowTextA(g_editBase, bufBase, 64);
                GetWindowTextA(g_editDynamic, bufDyn, 64);
                GetWindowTextA(g_editMaxDepth, bufDepth, 16);

                DWORD_PTR baseAddr = strtoull(bufBase, NULL, 16);
                DWORD_PTR dynAddr = strtoull(bufDyn, NULL, 16);
                int maxDepth = atoi(bufDepth);
                if (maxDepth < 1)
                    maxDepth = 3;

                g_positionalOffsets.clear();
                int count = (int)SendMessageA(g_listOffsets, LB_GETCOUNT, 0, 0);
                for (int i = 0; i < count; i++) {
                    char bufOff[64];
                    SendMessageA(g_listOffsets, LB_GETTEXT, (WPARAM)i, (LPARAM)bufOff);
                    char* offStr = bufOff;
                    if (_strnicmp(offStr, "0x", 2) == 0) {
                        offStr += 2;
                    }
                    DWORD_PTR offVal = strtoull(offStr, NULL, 16);
                    g_positionalOffsets.push_back(offVal);
                }

                ScanParams* sp = new ScanParams();
                sp->baseAddr = baseAddr;
                sp->dynamicAddr = dynAddr;
                sp->maxDepth = maxDepth;

                g_isScanning = true;
                CreateThread(NULL, 0, ScanThreadProc, sp, 0, NULL);
            }
            break;
        }
        case 2: {
            if (g_isScanning) {
                g_stopRequested = true;
                AppendConsoleAsync("Stop requested.\r\n");
            }
            break;
        }
        case 103: {
            char bufOff[64];
            GetWindowTextA(g_editOffsetEntry, bufOff, sizeof(bufOff));
            if (strlen(bufOff) > 0) {
                SendMessageA(g_listOffsets, LB_ADDSTRING, 0, (LPARAM)bufOff);
                SetWindowTextA(g_editOffsetEntry, "");
                int newCount = (int)SendMessageA(g_listOffsets, LB_GETCOUNT, 0, 0);
                SendMessageA(g_listOffsets, LB_SETTOPINDEX, (WPARAM)(newCount - 1), 0);
            }
            break;
        }
        case 104: {
            int sel = (int)SendMessageA(g_listOffsets, LB_GETCURSEL, 0, 0);
            if (sel != LB_ERR) {
                SendMessageA(g_listOffsets, LB_DELETESTRING, sel, 0);
            }
            break;
        }
        }
        break;
    }
    case WM_APPEND_CONSOLE: {
        char* msgBuf = (char*)lParam;
        if (msgBuf) {
            int currentLen = GetWindowTextLengthA(g_editConsole);
            if (currentLen > CONSOLE_MAX_CHARS) {
                int textLen = currentLen + 1;
                char* buffer = new char[textLen];
                GetWindowTextA(g_editConsole, buffer, textLen);
                int half = currentLen / 2;
                string newText = "\r\n-- Truncated --\r\n";
                newText.append(buffer + half);
                SetWindowTextA(g_editConsole, newText.c_str());
                delete[] buffer;
            }
            int len = GetWindowTextLengthA(g_editConsole);
            SendMessageA(g_editConsole, EM_SETSEL, (WPARAM)len, (LPARAM)len);
            SendMessageA(g_editConsole, EM_REPLACESEL, 0, (LPARAM)msgBuf);
            free(msgBuf);
        }
        break;
    }
    case WM_CTLCOLORSTATIC: {
        HWND hStatic = (HWND)lParam;
        if (hStatic == g_staticBase || hStatic == g_staticDynamic || hStatic == g_staticMaxDepth) {
            HDC hdcStatic = (HDC)wParam;
            SetBkMode(hdcStatic, TRANSPARENT);
            return (LRESULT)GetStockObject(NULL_BRUSH);
        }
        return DefWindowProcA(hWnd, message, wParam, lParam);
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcA(hWnd, message, wParam, lParam);
    }
    return 0;
}

DWORD WINAPI GuiThread(LPVOID lpParam) {
    WNDCLASSEXA wc = { 0 };
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = g_hInst;
    wc.lpszClassName = "PosOffsetsDynamicListScannerCleanFramed";
    RegisterClassExA(&wc);

    g_hWnd = CreateWindowA(
        "PosOffsetsDynamicListScannerCleanFramed",
        "Base2DynamicScanner",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        600,
        600,
        NULL,
        NULL,
        g_hInst,
        NULL
    );

    ShowWindow(g_hWnd, SW_SHOW);
    UpdateWindow(g_hWnd);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        g_hInst = hModule;
        DisableThreadLibraryCalls(g_hInst);
        CreateThread(NULL, 0, GuiThread, NULL, 0, NULL);
    }
    return TRUE;
}
