<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * This is a place to put custom environment checks, if there is not a better place.
 *
 * This library contains a collection of functions able to perform
 * some custom checks executed by environmental tests (automatically
 * executed on install & upgrade and under petition in the admin block).
 *
 * Any function in this library gets a environment_results object passed in.
 * It must return:
 * - null: if the test isn't relevant and must not be showed (ignored)
 * - the environment_results object that was passed in, with the status set to:
 *     - true: if passed
 *     - false: if failed
 *
 * @package    core
 * @subpackage admin
 * @copyright  (C) 2001-3001 Eloy Lafuente (stronk7) {@link http://contiento.com}
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

/**
 * Check whether a PHP runtime meets the PHP2Shell security floor.
 *
 * @param string $version PHP_VERSION for the running SAPI.
 * @param string $sapi PHP_SAPI for the running SAPI.
 * @param string|null $ubuntuversion Ubuntu VERSION_ID, when applicable.
 * @param bool $backportpackageverified Whether the exact allowed package is installed and verified.
 * @return bool
 */
function php2shell_php_version_supported(string $version, string $sapi, ?string $ubuntuversion = null,
        bool $backportpackageverified = false): bool {
    if (!preg_match('/\A8\.(2|3|4|5)\.(0|[1-9][0-9]*)\z/', $version, $matches)) {
        return false;
    }

    $branch = '8.' . $matches[1];
    $floor = ['8.2' => 35, '8.3' => 36, '8.4' => 27, '8.5' => 12][$branch];
    if ((int)$matches[2] >= $floor) {
        return true;
    }

    $supportedbackportsapi = in_array($sapi, ['cli', 'fpm-fcgi', 'apache2handler'], true);
    return $version === '8.3.6' && $ubuntuversion === '24.04' && $supportedbackportsapi && $backportpackageverified;
}

/**
 * Verify that the selected Ubuntu backport package owns an unchanged SAPI executable.
 *
 * @param string $sapi PHP_SAPI.
 * @param string $package Package name reported by dpkg metadata.
 * @param string $packageversion Package version reported by dpkg metadata.
 * @param string $path Canonical SAPI executable or Apache module path.
 * @param array $packagefiles Package-owned paths from the dpkg file list.
 * @param array $checksums Package checksums from the dpkg md5sums file.
 * @param string|null $actualchecksum Checksum of the current file.
 * @return bool
 */
function php2shell_backport_package_verified(string $sapi, string $package, string $packageversion,
        string $path, array $packagefiles, array $checksums, ?string $actualchecksum): bool {
    $expectedpackage = [
        'cli' => 'php8.3-cli',
        'fpm-fcgi' => 'php8.3-fpm',
        'apache2handler' => 'libapache2-mod-php8.3',
    ][$sapi] ?? null;
    if ($expectedpackage === null || $package !== $expectedpackage
            || $packageversion !== '8.3.6-0ubuntu0.24.04.13' || $path === '' || $actualchecksum === null) {
        return false;
    }

    $relativepath = ltrim(preg_replace('#^\\./#', '', $path), '/');
    $ownedpaths = array_filter($packagefiles, static function ($packagefile) use ($relativepath) {
        return ltrim(preg_replace('#^\\./#', '', trim($packagefile)), '/') === $relativepath;
    });
    $expectedchecksums = [];
    foreach ($checksums as $checksumline) {
        if (preg_match('/^([a-f0-9]{32})\\s+(.+)$/', trim($checksumline), $matches)
                && ltrim(preg_replace('#^\\./#', '', $matches[2]), '/') === $relativepath) {
            $expectedchecksums[] = $matches[1];
        }
    }

    return count($ownedpaths) === 1 && count($expectedchecksums) === 1
        && hash_equals($expectedchecksums[0], $actualchecksum);
}

/**
 * Verify the exact installed Ubuntu package and its SAPI file against local dpkg metadata.
 *
 * @param string $sapi PHP_SAPI.
 * @return bool
 */
function php2shell_ubuntu_backport_verified(string $sapi): bool {
    $package = [
        'cli' => 'php8.3-cli',
        'fpm-fcgi' => 'php8.3-fpm',
        'apache2handler' => 'libapache2-mod-php8.3',
    ][$sapi] ?? null;
    if ($package === null) {
        return false;
    }

    $packagepath = PHP_BINARY;
    if ($sapi === 'apache2handler') {
        $packagepath = '/usr/lib/apache2/modules/libphp8.3.so';
    }
    $path = realpath($packagepath);
    if ($path === false || !is_readable('/var/lib/dpkg/status')) {
        return false;
    }

    $packagestatus = null;
    $statuscontents = file_get_contents('/var/lib/dpkg/status');
    foreach (preg_split('/\\n\\n+/', trim($statuscontents)) as $packageinfo) {
        if (preg_match('/^Package: ' . preg_quote($package, '/') . '$/m', $packageinfo)
                && preg_match('/^Status: install ok installed$/m', $packageinfo)
                && preg_match('/^Version: ([^\\n]+)$/m', $packageinfo, $matches)) {
            $packagestatus = $matches[1];
            break;
        }
    }
    $filelistpath = '/var/lib/dpkg/info/' . $package . '.list';
    $checksumspath = '/var/lib/dpkg/info/' . $package . '.md5sums';
    if ($packagestatus === null || !is_readable($filelistpath) || !is_readable($checksumspath)) {
        return false;
    }

    return php2shell_backport_package_verified(
        $sapi,
        $package,
        $packagestatus,
        $path,
        file($filelistpath, FILE_IGNORE_NEW_LINES),
        file($checksumspath, FILE_IGNORE_NEW_LINES),
        hash_file('md5', $path),
    );
}

/**
 * Required environment check for the PHP2Shell security floor.
 *
 * @param environment_results $result
 * @return environment_results
 */
function php_check_php2shell(environment_results $result): environment_results {
    $ubuntuversion = null;
    $osrelease = @parse_ini_file('/etc/os-release');
    if (is_array($osrelease) && ($osrelease['ID'] ?? null) === 'ubuntu') {
        $ubuntuversion = $osrelease['VERSION_ID'] ?? null;
    }

    $backportverified = $ubuntuversion === '24.04' && PHP_VERSION === '8.3.6'
        && php2shell_ubuntu_backport_verified(PHP_SAPI);
    $result->setStatus(php2shell_php_version_supported(PHP_VERSION, PHP_SAPI, $ubuntuversion, $backportverified));
    return $result;
}
