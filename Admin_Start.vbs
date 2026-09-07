Set UAC = CreateObject("Shell.Application")
Set FSO = CreateObject("Scripting.FileSystemObject")
currentDir = FSO.GetParentFolderName(WScript.ScriptFullName)
batPath = currentDir & "\Start.bat"
UAC.ShellExecute "cmd.exe", "/c """ & batPath & """", "", "runas", 0
