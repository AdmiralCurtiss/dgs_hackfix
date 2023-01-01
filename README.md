The Great Ace Attorney PC Port Fixes
====================================

Feature Set:

- Animation framerate can now be set to arbitrary rate. (defaults to 60 but can be freely adjusted in the ini; set to 30 if you prefer the unpatched game's update rate)
- Several patches so player interaction properly adjusts to selected animation framerate -- some actions would become too fast or too slow by default. The patched values can also be adjusted in the ini.
- Resolution can now be set to arbitrary resolutions reported by your GPU/Monitor.
- CPU usage on some threads is now no longer unnecessarily high.
- Reports process as High-DPI aware so it doesn't get scaled by Windows.
- Fixes the crash some people experience when trying to 'pit' jury members.
- Has option (disabled by default) to move the multi-witness slider bar, as its default position may cover up some animations.

All options are can be enabled/disabled or configured in dgs.ini.

NOTE: The game expects to always run at the configured target framerate. If you're running this on a very low performance CPU or GPU and cannot consistently reach 60 FPS, you should change the FPS setting in the config file to the stock 30 for a better experience.

Compatible with the initial release version on Steam, both the build with Japanese text support and the build without. In the unlikely event they ever update the game it will stop working correctly.

Usage Instructions
==================

Windows
-------

- Place the contents of the 'windows' folder (DINPUT8.dll and dgs.ini) into same folder as TGAAC.exe, then run game from Steam.
- Adjust configuration in dgs.ini to taste.
- To uninstall just delete DINPUT8.dll.

Steam Deck
----------

- Switch to Desktop mode.
- Place the contents of the 'steamdeck' folder (dgs_hackfix.dll, dgs_patch_exe.exe, and dgs.ino) into same folder as TGAAC.exe.
- Add 'dgs_patch_exe.exe' as a non-Steam game.
- Right-click the new entry -> Properties -> Compatibility, tick the 'Force the use of a specific Steam Play compatibility tool' checkbox, and select Proton Experimental.
- Then run it once -- make sure the console window that appears says that the patch has been successfully applied.
- Adjust configuration in dgs.ini to taste.
- After that switch back to Gaming Mode and run the game as normal.
- To uninstall run 'dgs_patch_exe.exe' a second time -- make sure the console window says it has successfully removed the patch.

(Note: If you run 'dgs_patch_exe.exe' from Gaming Mode and get stuck, you can use STEAM+X to open the keyboard.)
