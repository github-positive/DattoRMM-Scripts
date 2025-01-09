Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Form Box
$form = New-Object System.Windows.Forms.Form
$form.Size = New-Object System.Drawing.Size(400, 350)  # Width/Height.
$form.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
$form.Location = New-Object System.Drawing.Point(([System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Width - $form.Width), ([System.Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Height - $form.Height))
$form.TopMost = $true  # Set to true to ensure the form stays on top
$form.ControlBox = $false  # Hide the standard title bar with close, minimize, and maximize buttons

# Logo (centered at the top)
$logoPictureBox = New-Object System.Windows.Forms.PictureBox
$logoPictureBox.Image = [System.Drawing.Image]::FromFile("C:\ProgramData\CentraStage\Brand\patchrebootwindow.png") 
$logoPictureBox.Size = New-Object System.Drawing.Size($form.Width, 50)  # Width/Height
$logoPictureBox.Location = New-Object System.Drawing.Point(0, 0)
$logoPictureBox.SizeMode = [System.Windows.Forms.PictureBoxSizeMode]::CenterImage

# Header
$headerLabel = New-Object System.Windows.Forms.Label
$headerLabel.Text = "Header text"
$headerLabel.AutoSize = $true
$headerLabel.Font = New-Object System.Drawing.Font("Arial", 12, [System.Drawing.FontStyle]::Bold)
$headerLabel.Location = New-Object System.Drawing.Point(([System.Math]::Round(($form.Width - $headerLabel.PreferredWidth) / 2)), 60)


##############################=========--Start Buttons Portion--========##################################
If($ENV:showRestartOption -eq $true){
    # Close button
    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = "Close"
    $closeButton.Add_Click({ $form.Close() })

    # Restart Button
    $restartButton = New-Object System.Windows.Forms.Button
    $restartButton.Text = "Restart Now"
    $restartButton.Add_Click({
        $form.Close()
        [System.Diagnostics.Process]::Start("shutdown", "/r /t 0") # Command to restart the PC immediately
    })

    # Buttons positions
    $buttonsTotalWidth = $closeButton.Width + $restartButton.Width + 10 # 10 pixels gap between buttons
    $centralPointX = [System.Math]::Round(($form.Width - $buttonsTotalWidth) / 2)
    $closeButton.Location = New-Object System.Drawing.Point($centralPointX, [System.Math]::Round(($form.Height - $closeButton.Height) - 50))
    $restartButton.Location = New-Object System.Drawing.Point([System.Math]::Round($closeButton.Location.X + $closeButton.Width + 10), $closeButton.Location.Y)
} else {
    # Close button
    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = "Close"
    $closeButton.Location = New-Object System.Drawing.Point([System.Math]::Round(($form.Width - $closeButton.Width) / 2), [System.Math]::Round(($form.Height - $closeButton.Height) - 50)) #button position 60 px from bottom
    $closeButton.Add_Click({ $form.Close() })
}

##############################=========--End Buttons Portion--========##################################

# Get meassurments to dynamically adjust the message space
$headerBottom = $headerLabel.Location.Y + $headerLabel.Height + 10
$buttonTopMargin = 10 
$buttonEffectiveTop = $form.Height - $closeButton.Height - 50 - $buttonTopMargin

# Message
$bodyLabel = New-Object System.Windows.Forms.Label
$bodyLabel.Text = "message text"
$bodyLabel.AutoSize = $false  # Set AutoSize to false as we set it static to not overlap on the button and header
$bodyLabel.Font = New-Object System.Drawing.Font("Arial", 10, [System.Drawing.FontStyle]::Regular) 
$bodyLabel.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$bodyLabel.Location = New-Object System.Drawing.Point(10, ($headerBottom + 10))
$bodyLabel.Height = $buttonEffectiveTop - $bodyLabel.Location.Y - 10  # Calculate space available for bodyLabel
$bodyLabel.Width = $form.Width - 20
$bodyLabel.Anchor = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right  # Set anchor to adjust the label size dynamically

# Add controls to the form
$form.Controls.Add($logoPictureBox)
$form.Controls.Add($headerLabel)
$form.Controls.Add($bodyLabel)
$form.Controls.Add($closeButton)
If($ENV:showRestartOption){$form.Controls.Add($restartButton)}

# Show the form
$form.Add_Shown({ $form.Activate() })
$form.ShowDialog()
