# Volatility
# Copyright (C) 2007,2008 Volatile Systems
#
# Volatools Basic
# Copyright (C) 2007 Komoku, Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details. 
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA 
#

"""
@author:       AAron Walters 
@license:      GNU General Public License 2.0 or later
@contact:      awalters@volatilesystems.com
@organization: Volatile Systems
"""

#pylint: disable-msg=C0111

#
# Details about the techniques used in this file can be found in 
# the following references:
#   - Opc0de, "Finding some non-exported kernel variables," 
#              http://www.rootkit.com/vault/Opc0de/GetVarXP.pdf 
#   - Alex Ionescu, "Getting Kernel Variables from KdVersionBlock, Part 2," 
#              http://www.rootkit.com/newsread.php?newsid=153
#

kpcr_addr =  0xffdff000
KUSER_SHARED_DATA = 0xFFDF0000