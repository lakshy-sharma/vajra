/*
Copyright © 2025 Lakshy Sharma lakshy.d.sharma@gmail.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
package eBPFHandlers

import (
	"vajra/internal/eBPFListeners"
	"vajra/internal/utilities"
)

// handleNetworkEvent handles network-related events
func (eh *EventHandler) handleNetworkEvent(event EventContext) {
	netEvent := event.EventData.(eBPFListeners.NetworkEvent)
	comm := utilities.ConvertCStringToGo(netEvent.Comm[:])

	eh.logger.Info().
		Uint32("event_type", event.EventType).
		Uint32("pid", netEvent.PID).
		Uint16("src_port", netEvent.SrcPort).
		Uint16("dst_port", netEvent.DstPort).
		Str("comm", comm).
		Msg("network event")
}
