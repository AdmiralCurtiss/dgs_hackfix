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

Compatible with the initial release version on Steam, both the build with Japanese text support and the build without, as well as the update from 2023-07-11. Will likely stop working if another update happens.

Usage Instructions
==================

Windows
-------

- Place the contents of the 'data' folder (DINPUT8.dll and dgs.ini) into same folder as TGAAC.exe, then run game from Steam.
- Adjust configuration in dgs.ini to taste.
- To uninstall just delete DINPUT8.dll.

Steam Deck
----------

- Switch to Desktop mode.
- Place the contents of the 'data' folder (DINPUT8.dll and dgs.ini) into same folder as TGAAC.exe.
- Right-click 'The Great Ace Attorney Chronicles' in the Steam game list and select 'Properties'.
- In the 'General' tab, add the following text (without the backticks!) into the Launch Options field at the bottom: `WINEDLLOVERRIDES=DINPUT8=n,b %command%`
- Adjust configuration in dgs.ini to taste.
- To uninstall, remove the text you entered in the Launch Options and delete DINPUT8.dll.
