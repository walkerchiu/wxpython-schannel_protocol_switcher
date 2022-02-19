from lib_registry import *
import winreg
import wx


class App(wx.Frame):

    def __init__(self, parent, title):
        self.frame_size = (320, 200)
        super(
            App,
            self).__init__(
            parent,
            title=title,
            size=self.frame_size,
            style=wx.MINIMIZE_BOX | wx.CAPTION | wx.CLOSE_BOX | wx.CLIP_CHILDREN)

        self.InitUI()
        self.Centre()

    def InitUI(self):
        panel = wx.Panel(self)

        font = wx.SystemSettings.GetFont(wx.SYS_SYSTEM_FONT)

        font.SetPointSize(5)

        vbox = wx.BoxSizer(wx.VERTICAL)

        hbox = wx.BoxSizer(wx.HORIZONTAL)
        str1 = wx.StaticText(panel, label='啟用以下協議將帶來資安風險，請謹慎使用：')
        hbox.Add(str1)
        vbox.Add(hbox, flag=wx.LEFT | wx.TOP, border=10)

        vbox.Add((-1, 10))

        vbox_checkbox = wx.BoxSizer(wx.VERTICAL)
        self.cb_tls_11 = wx.CheckBox(panel, label='啟用 TLS 1.1')
        vbox_checkbox.Add(self.cb_tls_11)
        self.cb_tls_10 = wx.CheckBox(panel, label='啟用 TLS 1.0')
        vbox_checkbox.Add(self.cb_tls_10)
        self.cb_ssl_30 = wx.CheckBox(panel, label='啟用 SSL 3.0')
        vbox_checkbox.Add(self.cb_ssl_30)
        self.cb_ssl_20 = wx.CheckBox(panel, label='啟用 SSL 2.0')
        vbox_checkbox.Add(self.cb_ssl_20)
        vbox.Add(vbox_checkbox, flag=wx.LEFT, border=10)

        vbox.Add((-1, 25))

        hbox5 = wx.BoxSizer(wx.HORIZONTAL)
        self.btn_submit = wx.Button(panel, label='確定', size=(70, 30))
        hbox5.Add(self.btn_submit)
        vbox.Add(hbox5, flag=wx.ALIGN_CENTER | wx.CENTER, border=10)

        panel.SetSizer(vbox)

        self.btn_submit.Bind(wx.EVT_BUTTON, self.OnSubmit)

        self.Protocols = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\Schannel\\Protocols'

        registry = Registry()
        registry.create_key(self.Protocols + "\\TLS 1.1\\Client", parents=True)
        registry.create_key(self.Protocols + "\\TLS 1.1\\Server", parents=True)
        registry.create_key(self.Protocols + "\\TLS 1.0\\Client", parents=True)
        registry.create_key(self.Protocols + "\\TLS 1.0\\Server", parents=True)
        registry.create_key(self.Protocols + "\\SSL 3.0\\Client", parents=True)
        registry.create_key(self.Protocols + "\\SSL 3.0\\Server", parents=True)
        registry.create_key(self.Protocols + "\\SSL 2.0\\Client", parents=True)
        registry.create_key(self.Protocols + "\\SSL 2.0\\Server", parents=True)

        registry.set_value(
            key=self.Protocols +
            "\\TLS 1.1\\Client",
            value_name='DisabledByDefault',
            value=1,
            value_type=winreg.REG_DWORD)
        registry.set_value(
            key=self.Protocols +
            "\\TLS 1.0\\Client",
            value_name='DisabledByDefault',
            value=1,
            value_type=winreg.REG_DWORD)
        registry.set_value(
            key=self.Protocols +
            "\\SSL 3.0\\Client",
            value_name='DisabledByDefault',
            value=1,
            value_type=winreg.REG_DWORD)
        registry.set_value(
            key=self.Protocols +
            "\\SSL 2.0\\Client",
            value_name='DisabledByDefault',
            value=1,
            value_type=winreg.REG_DWORD)

        self._check()

    def _check(self):
        registry = Registry()
        try:
            if registry.get_value(
                    self.Protocols +
                    "\\TLS 1.1\\Client",
                    'Enabled') and registry.get_value(
                    self.Protocols +
                    "\\TLS 1.1\\Server",
                    'Enabled'):
                self.cb_tls_11.SetValue(True)
            else:
                self.cb_tls_11.SetValue(False)
        except BaseException:
            self.cb_tls_11.SetValue(False)

        try:
            if registry.get_value(
                    self.Protocols +
                    "\\TLS 1.0\\Client",
                    'Enabled') and registry.get_value(
                    self.Protocols +
                    "\\TLS 1.0\\Server",
                    'Enabled'):
                self.cb_tls_10.SetValue(True)
            else:
                self.cb_tls_10.SetValue(False)
        except BaseException:
            self.cb_tls_10.SetValue(False)

        try:
            if registry.get_value(
                    self.Protocols +
                    "\\SSL 3.0\\Client",
                    'Enabled') and registry.get_value(
                    self.Protocols +
                    "\\SSL 3.0\\Server",
                    'Enabled'):
                self.cb_ssl_30.SetValue(True)
            else:
                self.cb_ssl_30.SetValue(False)
        except BaseException:
            self.cb_ssl_30.SetValue(False)

        try:
            if registry.get_value(
                    self.Protocols +
                    "\\SSL 2.0\\Client",
                    'Enabled') and registry.get_value(
                    self.Protocols +
                    "\\SSL 2.0\\Server",
                    'Enabled'):
                self.cb_ssl_20.SetValue(True)
            else:
                self.cb_ssl_20.SetValue(False)
        except BaseException:
            self.cb_ssl_20.SetValue(False)

    def OnSubmit(self, event):
        registry = Registry()

        if self.cb_tls_11.GetValue():
            registry.set_value(
                key=self.Protocols +
                "\\TLS 1.1\\Client",
                value_name='Enabled',
                value=1,
                value_type=winreg.REG_DWORD)
            registry.set_value(
                key=self.Protocols +
                "\\TLS 1.1\\Server",
                value_name='Enabled',
                value=1,
                value_type=winreg.REG_DWORD)
        else:
            registry.set_value(
                key=self.Protocols +
                "\\TLS 1.1\\Client",
                value_name='Enabled',
                value=0,
                value_type=winreg.REG_DWORD)
            registry.set_value(
                key=self.Protocols +
                "\\TLS 1.1\\Server",
                value_name='Enabled',
                value=0,
                value_type=winreg.REG_DWORD)

        if self.cb_tls_10.GetValue():
            registry.set_value(
                key=self.Protocols +
                "\\TLS 1.0\\Client",
                value_name='Enabled',
                value=1,
                value_type=winreg.REG_DWORD)
            registry.set_value(
                key=self.Protocols +
                "\\TLS 1.0\\Server",
                value_name='Enabled',
                value=1,
                value_type=winreg.REG_DWORD)
        else:
            registry.set_value(
                key=self.Protocols +
                "\\TLS 1.0\\Client",
                value_name='Enabled',
                value=0,
                value_type=winreg.REG_DWORD)
            registry.set_value(
                key=self.Protocols +
                "\\TLS 1.0\\Server",
                value_name='Enabled',
                value=0,
                value_type=winreg.REG_DWORD)

        if self.cb_ssl_30.GetValue():
            registry.set_value(
                key=self.Protocols +
                "\\SSL 3.0\\Client",
                value_name='Enabled',
                value=1,
                value_type=winreg.REG_DWORD)
            registry.set_value(
                key=self.Protocols +
                "\\SSL 3.0\\Server",
                value_name='Enabled',
                value=1,
                value_type=winreg.REG_DWORD)
        else:
            registry.set_value(
                key=self.Protocols +
                "\\SSL 3.0\\Client",
                value_name='Enabled',
                value=0,
                value_type=winreg.REG_DWORD)
            registry.set_value(
                key=self.Protocols +
                "\\SSL 3.0\\Server",
                value_name='Enabled',
                value=0,
                value_type=winreg.REG_DWORD)

        if self.cb_ssl_20.GetValue():
            registry.set_value(
                key=self.Protocols +
                "\\SSL 2.0\\Client",
                value_name='Enabled',
                value=1,
                value_type=winreg.REG_DWORD)
            registry.set_value(
                key=self.Protocols +
                "\\SSL 2.0\\Server",
                value_name='Enabled',
                value=1,
                value_type=winreg.REG_DWORD)
        else:
            registry.set_value(
                key=self.Protocols +
                "\\SSL 2.0\\Client",
                value_name='Enabled',
                value=0,
                value_type=winreg.REG_DWORD)
            registry.set_value(
                key=self.Protocols +
                "\\SSL 2.0\\Server",
                value_name='Enabled',
                value=0,
                value_type=winreg.REG_DWORD)

        wx.MessageBox("設定成功！請重新開機讓設定生效！", "操作提示", wx.OK | wx.ICON_INFORMATION)


def main():
    app = wx.App()
    ex = App(None, title='過時協議啟用切換器 0.1')
    ex.Show()
    app.MainLoop()


if __name__ == '__main__':
    main()
