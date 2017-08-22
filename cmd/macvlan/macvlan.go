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
	"fmt"
	"os"

	pb "github.com/lukegb/captivate/captivated"
	"google.golang.org/grpc"
	"gopkg.in/urfave/cli.v1"
)

var (
	mvc  pb.MACVLANClient
	conn *grpc.ClientConn
)

func main() {
	app := cli.NewApp()
	ctx := context.Background()

	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:  "addr",
			Value: "[2a07:1c44:3636:50::]:21001",
			Usage: "address of macvland server",
		},
	}
	app.Before = func(c *cli.Context) error {
		addr := c.String("addr")

		var err error
		conn, err = grpc.Dial(addr, grpc.WithInsecure())
		if err != nil {
			return err
		}

		mvc = pb.NewMACVLANClient(conn)

		return nil
	}
	app.After = func(c *cli.Context) error {
		if conn != nil {
			if err := conn.Close(); err != nil {
				return err
			}
		}
		return nil
	}

	app.Commands = []cli.Command{
		{
			Name:    "ls",
			Aliases: []string{"list"},
			Usage:   "list network interfaces",
			Action: func(c *cli.Context) error {
				resp, err := mvc.ListInterfaces(ctx, &pb.ListInterfacesRequest{})
				if err != nil {
					return err
				}

				for _, rintf := range resp.Interfaces {
					fmt.Printf("%s\n", rintf.Interface)
				}
				return nil
			},
		},
		{
			Name:    "lsmacs",
			Aliases: []string{"listmacs"},
			Usage:   "list known MACs",
			Action: func(c *cli.Context) error {
				resp, err := mvc.ListMACs(ctx, &pb.ListMACsRequest{})
				if err != nil {
					return err
				}

				for _, rmac := range resp.Macs {
					fmt.Printf("%s\n", rmac.Mac)
				}
				return nil
			},
		},
		{
			Name:  "get",
			Usage: "get MACs currently assigned to network interface(s)",
			Action: func(c *cli.Context) error {
				var indent string
				printName := false
				if c.NArg() == 0 {
					return fmt.Errorf("you must specify at least one network interface for get")
				} else if c.NArg() > 1 {
					indent = "\t"
					printName = true
				}

				for _, intf := range c.Args() {
					resp, err := mvc.GetInterface(ctx, &pb.GetInterfaceRequest{
						Interface: intf,
					})
					if err != nil {
						return fmt.Errorf("GetInterface(%q): %v", intf, err)
					}

					if printName {
						fmt.Println(resp.Interface)
					}
					for _, m := range resp.AuthorisedMac {
						fmt.Printf("%s%s\n", indent, m)
					}
				}
				return nil
			},
		},
		{
			Name:  "set",
			Usage: "assign MAC to network interface",
			Action: func(c *cli.Context) error {
				if c.NArg() != 2 {
					return fmt.Errorf("set [MAC] [interface name]")
				}
				mac := c.Args()[0]
				intf := c.Args()[1]
				_, err := mvc.Authorise(ctx, &pb.AuthoriseRequest{
					Interface: intf,
					Mac:       mac,
				})
				if err != nil {
					return fmt.Errorf("failed to Authorise: %v", err)
				}
				return nil
			},
		},
	}

	app.Run(os.Args)

}
