[app]

# (str) Title of your application
title = Meme Viewer

# (str) Package name
package.name = MemeViewer

# (str) Package domain (needed for android/ios packaging)
package.domain = org.hacklab

# (str) Source code where the main.py live
source.dir = .

# (list) Source files to include (let empty to include all the files)
source.include_exts = py,png,jpg,kv,atlas

# (list) List of inclusions using pattern matching
#source.include_patterns = assets/*,images/*.png

# (list) Source files to exclude (let empty to not exclude anything)
#source.exclude_exts = spec

# (list) List of directory to exclude (let empty to not exclude anything)
#source.exclude_dirs = tests, bin

# (list) List of exclusions using pattern matching
#source.exclude_patterns = license,images/*/*.jpg

# (str) Application versioning (method 1)
version = 1.0

# (str) Application versioning (method 2)
# version.regex = __version__ = ['"](.*)['"]
# version.filename = %(source.dir)s/main.py

# (list) Application requirements
# comma separated e.g. requirements = sqlite3,kivy
requirements = python,kivy,os,threading,time

# (str) Custom source folders for requirements
# Sets custom source for any requirements with recipes
# requirements.source.kivy = ../../kivy

# (str) Presplash of the application
#presplash.filename = %(source.dir)s/data/presplash.png

# (str) Icon of the application
#icon.filename = %(source.dir)s/data/icon.png

# (list) Supported orientations
# Valid options are: landscape, portrait, portrait-reverse or landscape-reverse
orientation = portrait

# (list) List of service to declare
#services = NAME:ENTRYPOINT_TO_PY,NAME2:ENTRYPOINT2_TO_PY


#
# Android specific
#

# (bool) Indicate if the application should be fullscreen or not
fullscreen = 1

# (list) Permissions
# We need internet permission for the background beacon
android.permissions = INTERNET, ACCESS_NETWORK_STATE

# (int) Target Android API, should be as high as possible.
# This helps with compatibility
android.api = 30

# (int) Minimum API your APK will support
android.minapi = 21

# (str) Android NDK directory (if empty, it will be automatically downloaded)
#android.ndk_path =

# (str) Android SDK directory (if empty, it will be automatically downloaded)
#android.sdk_path =

# (str) ANT directory (if empty, it will be automatically downloaded)
#android.ant_path =


#
# iOS specific
#

# (str) Path to the certificate.pem file
#ios.codesign_identity =

# (str) Path to the provisioning profile
#ios.provisioning_profile =

# (str) Python directory (if empty, it will be automatically created)
#ios.kivy_ios_dir =

# (bool) Whether to sign the code
#ios.sign = False


#
# Distribution
#

# (str) Icon for the distribution (used when creating packages)
#icon = %(source.dir)s/icon.png

# (str) Presplash for the distribution (used when creating packages)
#presplash = %(source.dir)s/presplash.png

# (int) Display orientation (0 landscape, 1 portrait)
#orientation = 1

# (list) Permissions
#permissions =


[buildozer]

# (int) Log level (0 = error only, 1 = info, 2 = debug (with command output))
log_level = 2

# (str) Path to build artifact storage
# build_dir = .buildozer

# (str) Path to build cache storage (signatures cache, apk cache, ...).
# If not set, use build_dir if set, or .buildozer by default.
# cache_dir =

# (str) Path to the specifications file (where requirements are fetched)
# spec_file =

# (str) User defined command to invoke on clean
# clean_command =

# (str) User defined command to invoke on distclean
# distclean_command =




