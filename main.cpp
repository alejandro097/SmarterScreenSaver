#include <windows.h>
#include <tlhelp32.h>
#include <thread>
#include <atomic>
#include <vector>
#include <string>
#include <fstream>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <audiopolicy.h>
#include <psapi.h>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "psapi.lib")

// === CONFIGURATION ===
constexpr DWORD MEDIA_GRACE_PERIOD_MS = 15000;    // 15 seconds pause after media stops
constexpr DWORD LOOP_INTERVAL_MS = 1000;          // 1 second loop

// === GLOBAL STATE ===
std::atomic<bool> isWhitelistedAppRunning(false);
std::atomic<bool> isMediaPlaying(false);
std::vector<std::string> whitelist;
std::string GetExecutableDirectory() {
    char exePath[MAX_PATH];
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    
    std::string path = exePath;
    size_t pos = path.find_last_of("\\/");
    if (pos != std::string::npos) {
        return path.substr(0, pos);
    }
    return "";
}

DWORD mediaStoppedTime = 0;
DWORD g_lastActiveSessionTime = 0;
DWORD IDLE_THRESHOLD_MS = 120000;   

// === UTILITY FUNCTIONS ===
DWORD GetIdleTime() {
    LASTINPUTINFO li = { sizeof(LASTINPUTINFO) };
    GetLastInputInfo(&li);
    return GetTickCount() - li.dwTime;
}

bool IsShellOrTaskbarFocused()
{
    HWND hwndForeground = GetForegroundWindow();
    if (!hwndForeground) return false;

    // Taskbar
    HWND hTaskbar = FindWindowW(L"Shell_TrayWnd", nullptr);
    if (hwndForeground == hTaskbar) return true;

    // Start button (on taskbar)
    HWND hStart = FindWindowW(L"Start", nullptr);
    if (hwndForeground == hStart) return true;

    // Sometimes the Start button is "Button" with taskbar parent
    wchar_t className[256];
    GetClassNameW(hwndForeground, className, 256);
    if (wcscmp(className, L"Button") == 0) {
        HWND hParent = GetParent(hwndForeground);
        if (hParent == hTaskbar) return true;
    }

    // Desktop
    HWND hDesktop = GetShellWindow();
    if (hwndForeground == hDesktop) return true;
    if (wcscmp(className, L"Progman") == 0) return true;
    if (wcscmp(className, L"WorkerW") == 0) return true;

    return false;
}

static HWND g_hTaskbar = nullptr;
static bool g_taskbarWasHidden = false;

void HideTaskbar()
{
    if (!g_hTaskbar)
        g_hTaskbar = FindWindowW(L"Shell_TrayWnd", nullptr);

    if (g_hTaskbar)
        ShowWindow(g_hTaskbar, SW_HIDE);
}

void ShowTaskbar()
{
    if (g_hTaskbar)
        ShowWindow(g_hTaskbar, SW_SHOW);
}

DWORD g_screensaverPID = 0;

void TriggerScreensaver() {
    char path[MAX_PATH];
    GetWindowsDirectoryA(path, MAX_PATH);
    strcat_s(path, "\\System32\\scrnsave.scr /s");

    STARTUPINFOA si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    CreateProcessA(nullptr, path, nullptr, nullptr, FALSE,
                   CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);

    g_screensaverPID = pi.dwProcessId;

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
	
	if (IsShellOrTaskbarFocused()) {
		HideTaskbar();
		g_taskbarWasHidden = true;
	}
}

void KillScreensaver() {
	if (g_taskbarWasHidden) {
		ShowTaskbar();
		g_taskbarWasHidden = false;
	}
	
	if (g_screensaverPID != 0) {
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, g_screensaverPID);
        if (hProc) {
            TerminateProcess(hProc, 0);
            CloseHandle(hProc);
            g_screensaverPID = 0;
        }
    }
}

void LoadWhitelist(const std::string& path) {
    std::ifstream file(path);
    std::string line;
    int lineNum = 1;
    
    while (std::getline(file, line)) {
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        
        if (!line.empty()) {
            whitelist.push_back(line);
        }
        lineNum++;
    }
    
    if (whitelist.empty()) {
        whitelist.push_back("chrome.exe");
        whitelist.push_back("msedge.exe");
    }
}

void LoadConfig(const std::string& path) {
    std::ifstream file(path);
    std::string line;
    
    while (std::getline(file, line)) {
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        
        if (line.empty() || line[0] == '#') continue; 
        
        size_t pos = line.find('=');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            std::string value = line.substr(pos + 1);
            
            key.erase(key.find_last_not_of(" \t") + 1);
            key.erase(0, key.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            
            if (key == "IDLE_THRESHOLD_MS") {
                try {
                    IDLE_THRESHOLD_MS = std::stoul(value);
                } catch (...) {
                }
            }
        }
    }
}

std::vector<DWORD> GetWhitelistedProcessIds() {
    std::vector<DWORD> pids;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return pids;

    PROCESSENTRY32 entry = { sizeof(PROCESSENTRY32) };
    if (Process32First(snapshot, &entry)) {
        do {
            for (const auto& name : whitelist) {
                if (_stricmp(entry.szExeFile, name.c_str()) == 0) {
                    pids.push_back(entry.th32ProcessID);
                }
            }
        } while (Process32Next(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return pids;
}

bool IsWhitelistedProcessRunning() {
    auto pids = GetWhitelistedProcessIds();
    return !pids.empty();
}

std::string GetProcessName(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return "Unknown";
    
    char processName[MAX_PATH];
    DWORD size = sizeof(processName);
    if (QueryFullProcessImageNameA(hProcess, 0, processName, &size)) {
        std::string name = processName;
        size_t pos = name.find_last_of("\\/");
        if (pos != std::string::npos) name = name.substr(pos + 1);
        CloseHandle(hProcess);
        return name;
    }
    
    CloseHandle(hProcess);
    return "Unknown";
}

// Helper function to check if an executable name matches whitelist
bool IsExecutableWhitelisted(const std::string& executableName) {
    for (const auto& whitelistedName : whitelist) {
        if (_stricmp(executableName.c_str(), whitelistedName.c_str()) == 0) {
            return true;
        }
    }
    return false;
}

#ifndef __IAudioMeterInformation_INTERFACE_DEFINED__
#define __IAudioMeterInformation_INTERFACE_DEFINED__

MIDL_INTERFACE("C02216F6-8C67-4B5B-9D00-D008E73E0064")
IAudioMeterInformation : public IUnknown
{
public:
    virtual HRESULT STDMETHODCALLTYPE GetPeakValue(float *pfPeak) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetMeteringChannelCount(UINT *pnChannelCount) = 0;
    virtual HRESULT STDMETHODCALLTYPE GetChannelsPeakValues(UINT32 u32ChannelCount, float *afPeakValues) = 0;
    virtual HRESULT STDMETHODCALLTYPE QueryHardwareSupport(DWORD *pdwHardwareSupportMask) = 0;
};

#endif

// --- GLOBAL AUDIO STATE ---
IMMDeviceEnumerator* g_pEnumerator = nullptr;
IMMDevice* g_pDevice = nullptr;
IAudioSessionManager2* g_pSessionManager = nullptr;
bool g_audioInitialized = false;

void CleanupAudio() {
    if (g_pSessionManager) { 
        g_pSessionManager->Release(); 
        g_pSessionManager = nullptr; 
    }
    if (g_pDevice) { 
        g_pDevice->Release(); 
        g_pDevice = nullptr; 
    }
    if (g_pEnumerator) { 
        g_pEnumerator->Release(); 
        g_pEnumerator = nullptr; 
    }
    if (g_audioInitialized) {
        CoUninitialize();
        g_audioInitialized = false;
    }
}

bool InitAudio() {
    if (g_audioInitialized) {
        CleanupAudio();
    }

    HRESULT hr = CoInitialize(nullptr);
    if (FAILED(hr)) return false;

    const GUID CLSID_MMDeviceEnumerator = {0xbcde0395,0xe52f,0x467c,{0x8e,0x3d,0xc4,0x57,0x92,0x91,0x69,0x2e}};
    const GUID IID_IMMDeviceEnumerator = {0xa95664d2,0x9614,0x4f35,{0xa7,0x46,0xde,0x8d,0xb6,0x36,0x17,0xe6}};
    const GUID IID_IAudioSessionManager2 = {0x77aa99a0,0x1bd6,0x484f,{0x8b,0xc7,0x2c,0x65,0x4c,0x9a,0x9b,0x6f}};

    hr = CoCreateInstance(CLSID_MMDeviceEnumerator, nullptr, CLSCTX_ALL,
                          IID_IMMDeviceEnumerator, (void**)&g_pEnumerator);
    if (FAILED(hr)) {
        CoUninitialize();
        return false;
    }

    // Use eMultimedia instead of eConsole for better multimedia app detection
    hr = g_pEnumerator->GetDefaultAudioEndpoint(eRender, eMultimedia, &g_pDevice);
    if (FAILED(hr)) {
        CleanupAudio();
        return false;
    }

    hr = g_pDevice->Activate(IID_IAudioSessionManager2, CLSCTX_ALL, nullptr, (void**)&g_pSessionManager);
    if (FAILED(hr)) {
        CleanupAudio();
        return false;
    }

    g_audioInitialized = true;
    return true;
}

bool IsAudioPlayingFromWhitelistedProcess() {
    if (!g_audioInitialized) return false;

    IAudioSessionEnumerator* pSessionEnumerator = nullptr;
    HRESULT hr = g_pSessionManager->GetSessionEnumerator(&pSessionEnumerator);
    if (FAILED(hr)) {
        CleanupAudio(); 
        return false;
    }

    int sessionCount = 0;
    hr = pSessionEnumerator->GetCount(&sessionCount);
    if (FAILED(hr)) {
        pSessionEnumerator->Release();
        CleanupAudio();  
        return false;
    }

    bool audioPlaying = false;
    bool hasActiveSession = false;
    
    for (int i = 0; i < sessionCount; i++) {
        IAudioSessionControl* pSessionControl = nullptr;
        hr = pSessionEnumerator->GetSession(i, &pSessionControl);
        if (FAILED(hr)) continue;

        IAudioSessionControl2* pSessionControl2 = nullptr;
        const GUID IID_IAudioSessionControl2 = {0xbfb7ff88,0x7239,0x4fc9,{0x8f,0xa2,0x07,0xc9,0x50,0xbe,0x9c,0x6d}};
        hr = pSessionControl->QueryInterface(IID_IAudioSessionControl2, (void**)&pSessionControl2);
        
        if (SUCCEEDED(hr)) {
            DWORD processId = 0;
            hr = pSessionControl2->GetProcessId(&processId);
            
            if (SUCCEEDED(hr) && processId != 0) { // Ignore system sessions (PID == 0)
                // Get the executable name for this PID and check against whitelist
                std::string executableName = GetProcessName(processId);
                
                if (IsExecutableWhitelisted(executableName)) {
                    AudioSessionState sessionState;
                    hr = pSessionControl->GetState(&sessionState);
                    
                    if (SUCCEEDED(hr)) {
                        if (sessionState == AudioSessionStateActive || sessionState == AudioSessionStateInactive) {
                            hasActiveSession = true;
                            if (g_lastActiveSessionTime == 0) {
                                g_lastActiveSessionTime = GetTickCount();
                            }
                            
                            IAudioMeterInformation* pMeter = nullptr;
                            const GUID IID_IAudioMeterInformation = {0xc02216f6,0x8c67,0x4b5b,{0x9d,0x00,0xd0,0x08,0xe7,0x3e,0x00,0x64}};
                            hr = pSessionControl->QueryInterface(IID_IAudioMeterInformation, (void**)&pMeter);
                            
                            if (SUCCEEDED(hr)) {
                                float peak = 0.0f;
                                hr = pMeter->GetPeakValue(&peak);
                                
                                if (SUCCEEDED(hr)) {
                                    if (peak > 0.001f) {
                                        audioPlaying = true;
                                        g_lastActiveSessionTime = GetTickCount();
                                    } else {
                                        DWORD timeSinceActive = GetTickCount() - g_lastActiveSessionTime;
                                        if (timeSinceActive < MEDIA_GRACE_PERIOD_MS) {
                                            audioPlaying = true;
                                        }
                                    }
                                }
                                pMeter->Release();
                            }
                        }
                    }
                }
            }
            pSessionControl2->Release();
        }
        pSessionControl->Release();
        
        if (audioPlaying) break;
    }

    if (!hasActiveSession) {
        g_lastActiveSessionTime = 0;
    }

    pSessionEnumerator->Release();
    return audioPlaying;
}

int main() {
    HANDLE hMutex = CreateMutexA(nullptr, FALSE, "Global\\ScreensaverManagerMutex");
    if (!hMutex) return 1;
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return 0; 
    }
    
	std::string exeDir = GetExecutableDirectory();
	LoadWhitelist(exeDir + "\\whitelist.txt");
	LoadConfig(exeDir + "\\app.config");

    bool screensaverActive = false;
    static bool wasMediaPlaying = false;
    
    bool audioReady = false;
    bool initialAudioSetup = false;

    while (true) {
        DWORD now = GetTickCount();
        
        if (!initialAudioSetup) {
            audioReady = InitAudio();
            if (audioReady) {
                initialAudioSetup = true; 
            } else {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                continue;
            }
        }
        
        if (!g_audioInitialized) {
            audioReady = InitAudio();
        }

        DWORD idleTime = GetIdleTime();
        auto whitelistedPids = GetWhitelistedProcessIds();
        bool match = !whitelistedPids.empty();
        isWhitelistedAppRunning = match;

        if (match) {
            bool currentMediaState = audioReady ? 
                IsAudioPlayingFromWhitelistedProcess() : false;

            if (wasMediaPlaying && !currentMediaState) {
                mediaStoppedTime = GetTickCount();
            } else if (!wasMediaPlaying && currentMediaState) {
                mediaStoppedTime = 0;
            }

            isMediaPlaying = currentMediaState;
            wasMediaPlaying = currentMediaState;

        } else {
            isMediaPlaying = false;
            wasMediaPlaying = false;
        }

        if (idleTime > IDLE_THRESHOLD_MS) {
            if (isWhitelistedAppRunning) {
                if (!isMediaPlaying) {
                    DWORD nowTick = GetTickCount();
                    DWORD sinceStopped = nowTick - mediaStoppedTime;

                    if (sinceStopped > MEDIA_GRACE_PERIOD_MS) {
                        if (!screensaverActive) {
                            TriggerScreensaver();
                            screensaverActive = true;
                        }
                    }
                }
            } else {
                if (!screensaverActive) {
                    TriggerScreensaver();
                    screensaverActive = true;
                }
            }
        }

        if (idleTime < 1000 && screensaverActive) {
            KillScreensaver();
            screensaverActive = false;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(LOOP_INTERVAL_MS));
    }

    CleanupAudio();
    return 0;
}
