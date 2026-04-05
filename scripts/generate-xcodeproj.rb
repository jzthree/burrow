#!/usr/bin/env ruby

require 'fileutils'
require 'pathname'

gem_home = File.expand_path('~/.gem/ruby/2.6.0')
$LOAD_PATH.unshift(File.join(gem_home, 'gems', 'xcodeproj-1.27.0', 'lib'))

require 'xcodeproj'

ROOT = File.expand_path('..', __dir__)
PROJECT_PATH = File.join(ROOT, 'PortKeeper.xcodeproj')
SUPPORT_DIR = File.join(ROOT, 'XcodeSupport')
INFO_PLIST_PATH = File.join(SUPPORT_DIR, 'PortKeeper-Info.plist')

FileUtils.rm_rf(PROJECT_PATH)
FileUtils.mkdir_p(SUPPORT_DIR)

unless File.exist?(INFO_PLIST_PATH)
  File.write(
    INFO_PLIST_PATH,
    <<~PLIST
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0">
      <dict>
        <key>CFBundleDevelopmentRegion</key>
        <string>en</string>
        <key>CFBundleDisplayName</key>
        <string>PortKeeper</string>
        <key>CFBundleExecutable</key>
        <string>$(EXECUTABLE_NAME)</string>
        <key>CFBundleIdentifier</key>
        <string>$(PRODUCT_BUNDLE_IDENTIFIER)</string>
        <key>CFBundleInfoDictionaryVersion</key>
        <string>6.0</string>
        <key>CFBundleName</key>
        <string>$(PRODUCT_NAME)</string>
        <key>CFBundlePackageType</key>
        <string>APPL</string>
        <key>CFBundleShortVersionString</key>
        <string>$(MARKETING_VERSION)</string>
        <key>CFBundleVersion</key>
        <string>$(CURRENT_PROJECT_VERSION)</string>
        <key>LSMinimumSystemVersion</key>
        <string>13.0</string>
        <key>LSUIElement</key>
        <true/>
        <key>NSHighResolutionCapable</key>
        <true/>
      </dict>
      </plist>
    PLIST
  )
end

project = Xcodeproj::Project.new(PROJECT_PATH)
project.root_object.attributes['LastSwiftMigration'] = '9999'

sources_group = project.main_group.new_group('Sources', 'Sources')
core_group = sources_group.new_group('PortKeeperCore', 'PortKeeperCore')
app_group = sources_group.new_group('PortKeeperMenuBar', 'PortKeeperMenuBar')
support_group = project.main_group.new_group('XcodeSupport', 'XcodeSupport')
support_group.new_file('PortKeeper-Info.plist')

core_target = project.new_target(:framework, 'PortKeeperCore', :osx, '13.0')
app_target = project.new_target(:application, 'PortKeeper', :osx, '13.0')

core_target.build_configurations.each do |config|
  config.build_settings['PRODUCT_NAME'] = 'PortKeeperCore'
  config.build_settings['PRODUCT_MODULE_NAME'] = 'PortKeeperCore'
  config.build_settings['PRODUCT_BUNDLE_IDENTIFIER'] = 'com.jianzhou.portkeeper.core'
  config.build_settings['DEFINES_MODULE'] = 'YES'
  config.build_settings['SWIFT_VERSION'] = '6.0'
  config.build_settings['MACOSX_DEPLOYMENT_TARGET'] = '13.0'
  config.build_settings['CODE_SIGN_STYLE'] = 'Automatic'
  config.build_settings['SKIP_INSTALL'] = 'YES'
  config.build_settings['GENERATE_INFOPLIST_FILE'] = 'YES'
  config.build_settings['ENABLE_APP_SANDBOX'] = 'NO'
end

app_target.build_configurations.each do |config|
  config.build_settings['PRODUCT_NAME'] = 'PortKeeper'
  config.build_settings['PRODUCT_BUNDLE_IDENTIFIER'] = 'com.jianzhou.portkeeper'
  config.build_settings['MARKETING_VERSION'] = '1.0'
  config.build_settings['CURRENT_PROJECT_VERSION'] = '1'
  config.build_settings['SWIFT_VERSION'] = '6.0'
  config.build_settings['MACOSX_DEPLOYMENT_TARGET'] = '13.0'
  config.build_settings['CODE_SIGN_STYLE'] = 'Automatic'
  config.build_settings['GENERATE_INFOPLIST_FILE'] = 'NO'
  config.build_settings['INFOPLIST_FILE'] = 'XcodeSupport/PortKeeper-Info.plist'
  config.build_settings['LD_RUNPATH_SEARCH_PATHS'] = ['$(inherited)', '@executable_path/../Frameworks']
  config.build_settings['ENABLE_APP_SANDBOX'] = 'NO'
  config.build_settings['ASSETCATALOG_COMPILER_APPICON_NAME'] = ''
end

Dir.glob(File.join(ROOT, 'Sources/PortKeeperCore/*.swift')).sort.each do |file|
  ref = core_group.new_file(Pathname(file).relative_path_from(Pathname(File.join(ROOT, 'Sources/PortKeeperCore'))).to_s)
  core_target.source_build_phase.add_file_reference(ref)
end

Dir.glob(File.join(ROOT, 'Sources/PortKeeperMenuBar/*.swift')).sort.each do |file|
  ref = app_group.new_file(Pathname(file).relative_path_from(Pathname(File.join(ROOT, 'Sources/PortKeeperMenuBar'))).to_s)
  app_target.source_build_phase.add_file_reference(ref)
end

app_target.add_dependency(core_target)
app_target.frameworks_build_phase.add_file_reference(core_target.product_reference)
embed_phase = app_target.copy_files_build_phases.find { |phase| phase.name == 'Embed Frameworks' } || app_target.new_copy_files_build_phase('Embed Frameworks')
embed_phase.symbol_dst_subfolder_spec = :frameworks
embed_build_file = embed_phase.add_file_reference(core_target.product_reference, true)
embed_build_file.settings = { 'ATTRIBUTES' => %w[CodeSignOnCopy RemoveHeadersOnCopy] }

project.build_configurations.each do |config|
  config.build_settings['SWIFT_VERSION'] = '6.0'
  config.build_settings['MACOSX_DEPLOYMENT_TARGET'] = '13.0'
end

project.save

scheme = Xcodeproj::XCScheme.new
scheme.add_build_target(app_target)
scheme.set_launch_target(app_target)
scheme.save_as(PROJECT_PATH, 'PortKeeper', true)

puts "Generated #{PROJECT_PATH}"
