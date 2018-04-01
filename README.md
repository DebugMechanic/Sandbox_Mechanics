# Sandbox_Mechanics

## A gentle introduction to Sessions:

Each program you have on your computer, when executed is considered a process. A process is a program which is being executed. Each process is the program code, a collection of threads, and other resources relating to the program.

Each process in Windows belongs to a single user who started that process, and each process also belongs to something called a Session. Each Session in Windows hosts a collection of Processes, Windows, Window Stations, Desktops, and several other resources including Services. 

You can see a list of all of the processes on your computer by going into Task Manager (taskmgr.exe) and clicking on the "Processes" tab. In this list you can see the Username of the user who started the process and also the Session that the process belongs to. By default Windows will not show you the Session each process belongs to but you can easily see it by clicking on the View menu item and then "Select Columns..." Turn on the option "Session ID".

Each process belongs to exactly 1 Session and each Session has a Session ID which identifies it. You cannot change a process' Session after the process is started. In Task Manager you will see at least 1 Session if you are using an operating system below Windows Vista and you will see at least 2 Sessions if you are using an operating system of Vista or above.

In Windows you are not limited to that initial number of Sessions though. There can be many different Sessions, there is a limit that can be reached but we'll say for the sake of conversation that you can potentially have infinite Sessions.

If you're using Vista or above, the first Session, Session 0 is where all of the NT services are started. The second Session above 0 is where the first logged on user's programs will be started.

More Sessions than what I mentioned will occur anytime you have multiple users logged into the same machine. You can have multiple users logged into the same machine via Terminal Services, Remote Desktop, or multi user logins onto the same machine via switch-user. For each additional login operation that you make, a new Session is made.

More information on Sessions can be found here:
https://brianbondy.com/blog/100/understanding-windows-at-a-deeper-level-sessions-window-stations-and-desktops



## Sandbox Mechanics Overview:


Operating Systems Supported:
	Windows 7   -- Supported.
	Windows 10 -- Supported.


		
Project: 	Sandbox_Mechanics	Solution
Loader: 	Toolbox.exe	Master Interface Project
x64_Injector	x64_Injector.exe	64 bit Injection Project
x64_UM_Tracer	x64_UM_Tracer.dll	64 bit template tracer .dll Project
x86_Injector	x86_Injector.exe	32 bit Injection Project
x86_UM_Tracer	x86_UM_Tracer.dll	32 bit template tracer .dll Project

Help:

[code]Toolbox Build v1.0 -- By DebugMechanic

Usage:
        --help    : Print Usage...
        --exe     : (Exe To Trace) -- Ex. C:\Victim_EXE_Location\Victim.exe
        --dll     : (Tracer Dll)   -- Ex. C:\Custom_DLL_Location\Custom.dll

Press any key to continue . . .[/code]

## Usage:

x64 Test :
Toolbox.exe --exe "C:\Windows\notepad.exe" --dll "C:\Users\Administrator\Documents\visual studio 2013\Projects\Sandbox_Mechanics\x64\Debug\x64_UM_Tracer.dll"

x86 Test :
Toolbox.exe --exe "C:\Program Files (x86)\HxD\HxD.exe" --dll “C:\Users\Administrator\Documents\visual studio 2013\Projects\Sandbox_Mechanics\Debug\x86_UM_Tracer.dll"

As you can see from the locations above. I used Visual Studio 2013.

You will need the "Visual C++ Redistributable Packages for Visual Studio 2013" found here:
https://www.microsoft.com/en-us/download/details.aspx?id=40784
