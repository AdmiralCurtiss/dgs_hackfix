Hackfix for a few issues in the PC port:
- Animation framerate can now be set to arbitrary rate. (defaults to 60 but can be freely adjusted in the ini; set to 30 if you prefer the unpatched game's update rate)
- Cursor and camera movement speed properly adjust to selected framerate, and can be freely adjusted if desired.
- Resolution can now be set to arbitrary resolutions reported by your GPU/Monitor.
- CPU usage on some threads is now no longer unnecessarily high.
- Reports process as High-DPI aware so it doesn't get scaled by Windows.
- Attempt at fixing the crash some people experience when interacting with the Jury.

All options are can be enabled/disabled or configured in dgs.ini.

Make sure you have the x64 Visual Studio 2019 runtime installed.
https://support.microsoft.com/en-us/topic/the-latest-supported-visual-c-downloads-2647da03-1eea-4433-9aff-95f26a218cc0
https://aka.ms/vs/16/release/vc_redist.x64.exe

How to use:

Place DINPUT8.dll and dgs.ini in same folder as TGAAC.exe, then run game from Steam.
Adjust configuration in dgs.ini if necessary.
To uninstall just delete DINPUT8.dll.

This will break if the game gets updated, but that hopefully means they'll properly fix some of these issues...
