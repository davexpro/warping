package main

import (
	"log"
	"math/rand"
	"os"
	"time"

	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
)

var (
	flags = []cli.Flag{
		&cli.IntFlag{
			Name:    "threads",
			Aliases: []string{"t"},
			Value:   32,
			Usage:   "测试延迟的线程数，默认值 32。根据系统和路由器性能可适当增加或减少，最大值为 1024。",
		},
		&cli.IntFlag{
			Name:    "count",
			Aliases: []string{"c", "n"},
			Value:   16,
			Usage:   "对每个地址进行测试的次数，默认值 16、取值范围 8 到 128。",
		},
		&cli.BoolFlag{
			Name:    "quick",
			Aliases: []string{"q"},
			Value:   true,
			Usage:   "快速模式，只扫描 2048 个地址（ip:port）。默认开启，-q=false 可关闭。",
		},
		&cli.StringFlag{
			Name:  "pub",
			Value: WarpPublicKey,
			Usage: "自定义的 Warp 的 wg 公钥，默认 Warp 官方节点公钥。",
		},
		&cli.StringFlag{
			Name:  "pri",
			Value: "",
			Usage: "自定义的 Warp 的 wg 私钥。",
		},
	}
	commands = []*cli.Command{
		{
			Name:        "run",
			Usage:       "",
			UsageText:   "",
			Description: "开始测试最优的 Warp 地址",
			Action:      runWarping,
			Flags:       flags,
		},
	}
)

func main() {
	// init cli
	app := &cli.App{
		Name:     "warping",
		Usage:    "warping <https://github.com/DavexPro/warping>",
		Version:  "v0.1.0",
		Writer:   os.Stdout,
		Flags:    nil,
		Commands: commands,
	}

	// init rand seed
	rand.New(rand.NewSource(time.Now().UnixNano()))

	// run the cli
	err := app.Run(os.Args)
	if err != nil {
		log.Println(err.Error())
	}
}

func runWarping(c *cli.Context) error {
	// 0. params check
	threads, count := c.Int("threads"), c.Int("count")
	if threads < 1 || threads > 1024 {
		color.Red("[x] 线程数的取值应该在 [1, 1024] 之间")
		return nil
	}

	if count < 8 || count > 128 {
		color.Red("[x] 测试次数的取值应该在 [8, 128] 之间")
		return nil
	}

	if c.String("pri") != "" {
		if _, err := getNoisePrivateKeyFromBase64(c.String("pri")); err != nil {
			color.Red("[x] wireguard 的私钥格式有误")
			return nil
		}
	}
	if c.String("pub") != "" {
		if _, err := getNoisePublicKeyFromBase64(c.String("pub")); err != nil {
			color.Red("[x] wireguard 的公钥格式有误")
			return nil
		}
	}

	// 1. init warping handler
	w := NewWarping(threads, count, c.Bool("quick"))

	// 2. set priKey if possible
	if c.String("pri") != "" {
		err := w.SetHandshakePacket(c.String("pub"), c.String("pri"))
		if err != nil {
			color.Red("[x] 构造 wg 握手包失败，请联系作者")
			return nil
		}
	}

	// 3. run it
	w.Run()
	return nil
}
