## IDA WaitBoxEx

April 2020, Updated 2025 for IDA 9, By Sirmabus
A full featured IDA Pro wait box replacement with progress bar and customization options.

#### Features

* A "determinate" or "indeterminate" progress bar.
* A minimize button.
* Facilitates Qt CSS style sheets application for customization.
  Here one can change colors, the font, positions, labels, add texture, etc.
* Facilitates the changing of the title bar icon for yet more customization.
* A Windows 7 style taskbar progress indicator.
* Low cancel-check overhead using the `isUpdateTime()` method.

#### Fixes IDA issues

* Fixes the IDA wait box and main window freeze/stall/hang-up issue.
* Wait box works as a direct child of the main window; avoiding the odd separate
  window you see when you tab/switched the default one.
* Working "Cancel" button that instantly responds to user input.
* The close 'X' button is enabled, acting as an alternate "Cancel" button.

Pretty much the same usage as the default IDA `show_wait_box()` API call.

#### Example

#include "WaitBoxEx.h"

```cpp
WaitBox::show();
do
{
	// Check if canceled and update progress
	if (WaitBox::isUpdateTime())
		if (WaitBox::updateAndCancelCheck(progressPercent))
			break;

	...
}
while(...);
WaitBox::hide();
```

See the "Plugin Example" project.
You don't need to have the Qt development environment installed to use it.
But obviously you'll need it if you want to make modifications.