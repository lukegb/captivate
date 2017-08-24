/*
Copyright 2017 Luke Granger-Brown

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"database/sql"
	"fmt"
	"net"
)

var (
	defaultSubnet = 1
)

type Database struct {
	c *sql.DB
}

func NewDatabase(ctx context.Context, c *sql.DB) (*Database, error) {
	if err := c.PingContext(ctx); err != nil {
		return nil, err
	}
	return &Database{c: c}, nil
}

func (db *Database) MarkDeviceSeen(ctx context.Context, mac net.HardwareAddr) error {
	_, err := db.c.ExecContext(ctx, "UPDATE device SET last_seen_at=NOW() WHERE mac=$1", macForDB(mac))
	return err
}

func (db *Database) GetVLANForDevice(ctx context.Context, mac net.HardwareAddr) (uint32, error) {
	return db.getVLANForDevice(ctx, mac, true)
}

func macForDB(mac net.HardwareAddr) []byte {
	return []byte(mac.String())
}

func (db *Database) getVLANForDevice(ctx context.Context, mac net.HardwareAddr, retry bool) (uint32, error) {
	// do we already know what this should be?
	row := db.c.QueryRowContext(ctx, `SELECT vlan_id FROM device WHERE mac=$1`, macForDB(mac))

	var vlanID uint32
	if err := row.Scan(&vlanID); err == nil {
		return vlanID, nil
	} else if err != sql.ErrNoRows {
		return 0, err
	}

	if !retry {
		return 0, fmt.Errorf("getVLANForDevice could not find the record it just inserted")
	}

	// we don't, insert a valid default record and try again
	_, err := db.c.ExecContext(ctx, `INSERT INTO device (mac, created_at, last_seen_at) VALUES ($1, NOW(), NOW())`, macForDB(mac))
	if err != nil {
		return 0, err
	}
	// do the select again
	return db.getVLANForDevice(ctx, mac, false)
}

func (db *Database) SetUserForDevice(ctx context.Context, mac net.HardwareAddr, email string) error {
	// get the user entry
	var userID int
	var userDefaultVLANID int
	// can't use DO NOTHING since we want the value to be returned
	err := db.c.QueryRowContext(ctx, "INSERT INTO \"user\" (email) VALUES ($1) ON CONFLICT (email) DO UPDATE SET email=EXCLUDED.email RETURNING id, default_vlan_id", email).Scan(&userID, &userDefaultVLANID)
	if err != nil {
		return err
	}

	_, err = db.c.ExecContext(ctx, `INSERT INTO device (mac, user_id, vlan_id, created_at, last_seen_at) VALUES ($1, $2, $3, NOW(), NOW()) ON CONFLICT (mac) DO UPDATE SET user_id=EXCLUDED.user_id, vlan_id=EXCLUDED.vlan_id, last_seen_at=EXCLUDED.last_seen_at`, macForDB(mac), userID, userDefaultVLANID)
	if err != nil {
		return err
	}

	return nil
}

/*
type Device struct {
	ID         uint
	MAC        net.HardwareAddr
	UserID     uint
	VLANID     uint
	CreatedAt  time.Time
	LastSeenAt time.Time
}

func toNullTime(t time.Time) *pq.NullTime {
	return &pq.NullTime{
		Time:  t,
		Valid: !t.IsZero(),
	}
}

func fromNullTime(nt pq.NullTime) time.Time {
	if !nt.Valid {
		var t time.Time
		return t
	}
	return nt.Time
}

func (db *Database) GetDeviceByMAC(ctx context.Context, mac net.HardwareAddr) (Device, error) {
	var d Device

	row, err := db.c.QueryRowContext(ctx, "SELECT id, mac, user_id, vlan_id, created_at, last_seen_at FROM device WHERE mac=$1", mac)
	if err != nil {
		return d, err
	}

	var lastSeenAtNT pq.NullTime
	if err := row.Scan(&d.ID, &d.MAC, &d.UserID, &d.VLANID, &d.CreatedAt, &lastSeenAtNT); err != nil {
		return d, err
	}
	d.LastSeenAt = fromNullTime(lastSeenAtNT)

	return d, nil
}

func (db *Database) SaveDevice(ctx context.Context, d Device) (Device, error) {
	if d.ID == 0 {
		// insert
		row, err := db.c.QueryRowContext(ctx, "INSERT INTO device (mac, user_id, vlan_id, created_at, last_seen_at) VALUES ($1, $2, $3, NOW(), $4) RETURNING (id, created_at)", d.MAC, d.UserID, d.VLANID, toNullTime(d.LastSeenAt))
		if err != nil {
			return d, err
		}

		if err := row.Scan(&d.ID, &d.CreatedAt); err != nil {
			return d, err
		}
		return d, nil
	}

	// update
	if err := db.c.ExecContext(ctx, "UPDATE device SET mac=$1, user_id=$2, vlan_id=$3, last_seen_at=$4", d.MAC, d.UserID, d.VLANID, toNullTime(d.LastSeenAt)); err != nil {
		return d, err
	}
	return d, nil
}
*/
