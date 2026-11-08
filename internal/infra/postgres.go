package infra 
import (
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"fmt"
)

func ConnectDB(c context.Context,dsn string) (*pgxpool.Pool, error) {
	db, err := pgxpool.New(c, dsn)
	if err != nil {
		return nil, err
	}

	if err := db.Ping(c); err != nil {
		db.Close()
		return nil,err
	}
	fmt.Print("dbPool init success")
	return db, nil 
}