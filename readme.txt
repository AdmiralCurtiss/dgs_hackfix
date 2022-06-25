Hackfix for a few issues in the PC port:
- Animation framerate can now be set to arbitrary rate. (defaults to 60 but can be freely adjusted in the ini; set to 30 if you prefer the unpatched game's update rate)
- Several patches so player interaction properly adjusts to selected animation framerate -- some actions would become too fast or too slow by default. The patched values can also be adjusted in the ini.
- Resolution can now be set to arbitrary resolutions reported by your GPU/Monitor.
- CPU usage on some threads is now no longer unnecessarily high.
- Reports process as High-DPI aware so it doesn't get scaled by Windows.
- Fixes the crash some people experience when trying to 'pit' jury members.
- Has option (disabled by default) to move the multi-witness slider bar, as its default position may cover up some animations.

All options are can be enabled/disabled or configured in dgs.ini.

NOTE: The game expects to always run at the configured target framerate. If you're running this on a very low performance CPU or GPU and cannot consistently reach 60 FPS, you should change the FPS setting in the config file to the stock 30 for a better experience.



How to use:

Make sure you have the x64 Visual Studio 2019 runtime installed.
https://support.microsoft.com/en-us/topic/the-latest-supported-visual-c-downloads-2647da03-1eea-4433-9aff-95f26a218cc0
https://aka.ms/vs/16/release/vc_redist.x64.exe

Place DINPUT8.dll and dgs.ini in same folder as TGAAC.exe, then run game from Steam.
Adjust configuration in dgs.ini if necessary.
To uninstall just delete DINPUT8.dll.




This will break if the game gets updated, but I suspect they're never going to, considering they haven't in the year or so since the game has been released.
