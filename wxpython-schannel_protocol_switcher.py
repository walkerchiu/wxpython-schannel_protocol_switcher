import winreg

import wx


class ProtocolSwitcher(wx.Frame):
    """
    Main application class for the protocol switcher.

    Args:
    - parent: The parent window.
    - title: The title of the window.
    """

    def __init__(self, parent, title):
        super(ProtocolSwitcher, self).__init__(
            parent,
            title=title,
            size=(320, 200),
            style=wx.MINIMIZE_BOX | wx.CAPTION | wx.CLOSE_BOX | wx.CLIP_CHILDREN,
        )

        self.InitUI()
        self.Centre()

    def InitUI(self):
        """
        Initializes the user interface.
        """
        panel = wx.Panel(self)

        font = wx.SystemSettings.GetFont(wx.SYS_SYSTEM_FONT)
        font.SetPointSize(10)

        vbox = wx.BoxSizer(wx.VERTICAL)

        protocols_label = wx.StaticText(
            panel, label="Enable the following protocols with caution:"
        )
        vbox.Add(protocols_label, flag=wx.LEFT | wx.TOP, border=10)

        vbox.Add((-1, 10))

        # Create checkboxes for each protocol
        checkboxes = [
            ("Enable TLS 1.1", "TLS 1.1"),
            ("Enable TLS 1.0", "TLS 1.0"),
            ("Enable SSL 3.0", "SSL 3.0"),
            ("Enable SSL 2.0", "SSL 2.0"),
        ]

        for label, protocol in checkboxes:
            checkbox = wx.CheckBox(panel, label=label)
            vbox.Add(checkbox, flag=wx.LEFT, border=10)
            setattr(self, f"cb_{protocol.lower().replace(' ', '_')}", checkbox)

        vbox.Add((-1, 25))

        submit_btn = wx.Button(panel, label="Submit", size=(70, 30))
        vbox.Add(submit_btn, flag=wx.ALIGN_CENTER | wx.CENTER, border=10)

        panel.SetSizer(vbox)

        submit_btn.Bind(wx.EVT_BUTTON, self.OnSubmit)

        # List of protocols to handle
        self.protocols = ["TLS 1.1", "TLS 1.0", "SSL 3.0", "SSL 2.0"]

        # Check the current status of the checkboxes
        self._check()

    def _check(self):
        """
        Check the current status of the protocol checkboxes.
        """
        for protocol in self.protocols:
            key = f"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Schannel\\Protocols\\{protocol}\\Client"
            try:
                enabled = winreg.QueryValueEx(
                    winreg.HKEY_LOCAL_MACHINE, key + "\\Enabled"
                )[0]
                getattr(self, f"cb_{protocol.lower().replace(' ', '_')}").SetValue(
                    bool(enabled)
                )
            except FileNotFoundError:
                pass

    def OnSubmit(self, event):
        """
        Handle the submit button click event.
        Update the registry settings based on checkbox values.
        """
        for protocol in self.protocols:
            key = f"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Schannel\\Protocols\\{protocol}\\Client"
            value = (
                1
                if getattr(self, f"cb_{protocol.lower().replace(' ', '_')}").GetValue()
                else 0
            )
            winreg.SetValueEx(
                winreg.HKEY_LOCAL_MACHINE, key + "\\Enabled", 0, winreg.REG_DWORD, value
            )

        wx.MessageBox(
            "Settings saved! Please restart your computer for the changes to take effect!",
            "Operation Prompt",
            wx.OK,
        )


def main():
    app = wx.App()
    ex = ProtocolSwitcher(None, title="Protocol Switcher 0.1")
    ex.Show()
    app.MainLoop()


if __name__ == "__main__":
    main()
