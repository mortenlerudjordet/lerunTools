import-module operationsmanager

get-scomresourcepool –displayname “notifications resource pool” | set-scomresourcepool –enableautomaticmembership $true