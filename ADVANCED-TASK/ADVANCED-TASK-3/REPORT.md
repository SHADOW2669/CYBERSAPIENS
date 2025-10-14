# Mobile Application Penetration Testing Methodology

## Reconnaissance

This is the pre-work stage where the tester learns as much as possible regarding the target mobile app. The aim is to learn the app's behavior, the technologies it employs, and the possible attack surface. Tasks involve:

  * Reading the app's features on the app store.
  * Discovering the backend servers and APIs the app uses.
  * Downloading the application package to analyze.

## Static Analysis

Static Application Security Testing (SAST) is the process of analyzing the application's code and configuration files without executing the app. It is similar to checking a building's blueprints for design issues. The major tasks are:

  * Decompiling the code to search for hardcoded secrets such as passwords or API keys.
  * Scanning configuration files for security misconfigurations.
  * Detecting insecure coding practices that may result in vulnerabilities.

## Dynamic Analysis

Dynamic Application Security Testing (DAST) is testing the app while running on a physical device or emulator. This is similar to testing locks and alarms on a building in real-time. Typical activities include:

  * Capturing network traffic between the app and its server to identify API vulnerabilities.
  * Checking the file system to determine whether the app insecurely saves sensitive information on the device.
  * Runtime manipulation to evade security measures such as root detection or SSL pinning in order to perform more in-depth tests.

## Reporting

This is the last and most important phase. All the weaknesses and vulnerabilities found throughout the **Static** and **Dynamic** analysis processes are listed in a detailed report. The report lays out each discovery, gives it a threat level, and offers clear, actionable suggestions for how the developers should address the problems and make the app more secure overall.

-----

# Installation Steps in Ubuntu

## 1\. Prerequisites for Ubuntu

### Install KVM for Better Performance

For the emulator to run smoothly, you need to install and configure KVM (Kernel-based Virtual Machine). This allows the emulator to use hardware virtualization. Open a terminal and run the following commands:

```bash
# Install KVM and supporting packages
sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils

# Add your user to the kvm and libvirt groups
sudo adduser $USER kvm
sudo adduser $USER libvirt
```

### Install Android Studio

The easiest way to install Android Studio on Ubuntu is using the Snap store.

```bash
sudo snap install android-studio --classic
```

## 2\. Emulator Creation Steps

1.  **Open the Virtual Device Manager**

      * Launch Android Studio. From the welcome screen, click on the **More Actions** dropdown and select **Virtual Device Manager**.
      * If you already have a project open, you can find it in the top menu under **Tools \> Device Manager**.

2.  **Create a New Virtual Device**

      * In the Device Manager window, click the **+ Create device** button.

3.  **Select Hardware**

      * Choose a device profile to emulate. Selecting a recent Pixel device is a good default choice. Click **Next**.

4.  **Select a System Image**

      * You need to select an Android OS version to run on your emulator.
      * You may need to click the **Download** icon next to a version (e.g., Tiramisu, API 33) to download it first.

    > **Pro-Tip for Pentesting:** It's highly recommended to choose a system image that does **not** have the Google Play Store icon. The "Google APIs" images are often easier to root, which is essential for many security testing tasks.

      * Click **Next** after selecting an image.

5.  **Configure and Finish**

      * Give your AVD a name or leave the default. You can also adjust advanced settings like the amount of RAM. Click **Finish**.

6.  **Launch the Emulator**

      * Your new virtual device will now appear in the Device Manager list. Click the **Play icon (▶)** in the Actions column to start it.
      * The emulator will now boot up in a new window, ready for you to install and test applications.