#include "threatfusion/Process.h"
#include <stdexcept>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/wait.h>
#include <unistd.h>
#endif

namespace threatfusion {
#ifdef _WIN32
static std::string windowsArgument(const std::string& value) {
    std::string escaped = "\"";
    std::size_t slashes = 0;
    for (char c : value) {
        if (c == '\\') { ++slashes; continue; }
        escaped.append(c == '"' ? slashes * 2 + 1 : slashes, '\\');
        slashes = 0;
        escaped += c;
    }
    escaped.append(slashes * 2, '\\');
    return escaped + '"';
}
#endif

std::string processOutput(const std::string& executable, const std::vector<std::string>& arguments) {
    std::string output;
    char buffer[8192];
#ifdef _WIN32
    SECURITY_ATTRIBUTES security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE reader, writer;
    if (!CreatePipe(&reader, &writer, &security, 0)) throw std::runtime_error("Cannot create process pipe");
    SetHandleInformation(reader, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOA startup{}; startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup.wShowWindow = SW_HIDE; startup.hStdOutput = writer; startup.hStdError = writer;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION process{};
    std::string command = windowsArgument(executable);
    for (const auto& argument : arguments) command += ' ' + windowsArgument(argument);
    if (!CreateProcessA(nullptr, command.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) {
        CloseHandle(reader); CloseHandle(writer);
        throw std::runtime_error("Cannot start executable: " + executable);
    }
    CloseHandle(writer);
    DWORD received;
    while (ReadFile(reader, buffer, sizeof(buffer), &received, nullptr) && received) output.append(buffer, received);
    CloseHandle(reader);
    WaitForSingleObject(process.hProcess, INFINITE);
    DWORD code; GetExitCodeProcess(process.hProcess, &code);
    CloseHandle(process.hProcess); CloseHandle(process.hThread);
#else
    int descriptors[2];
    if (pipe(descriptors)) throw std::runtime_error("Cannot create process pipe");
    auto child = fork();
    if (child == 0) {
        close(descriptors[0]); dup2(descriptors[1], STDOUT_FILENO); dup2(descriptors[1], STDERR_FILENO); close(descriptors[1]);
        std::vector<char*> argv{const_cast<char*>(executable.c_str())};
        for (const auto& argument : arguments) argv.push_back(const_cast<char*>(argument.c_str()));
        argv.push_back(nullptr); execvp(executable.c_str(), argv.data()); _exit(127);
    }
    close(descriptors[1]);
    if (child < 0) { close(descriptors[0]); throw std::runtime_error("Cannot fork process"); }
    ssize_t received;
    while ((received = read(descriptors[0], buffer, sizeof(buffer))) > 0) output.append(buffer, static_cast<std::size_t>(received));
    close(descriptors[0]);
    int status; waitpid(child, &status, 0);
    int code = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
#endif
    if (code != 0) throw std::runtime_error("Process failed: " + executable + "\n" + output);
    return output;
}
}
