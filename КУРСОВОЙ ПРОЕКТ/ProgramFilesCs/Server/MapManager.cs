using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace server
{
    public enum TileType : byte
    {
        Empty = 0,
        Wall = 1,
        Bush = 2,
        SteelWall = 3,
        Player1Spawn = 11,
        Player2Spawn = 12,
        Player3Spawn = 13,
        Player4Spawn = 14,
    }


    public class GameMap
    {
        public TileType[,] mat;
        public int width => mat.GetLength(1);
        public int height => mat.GetLength(0);

        public static int TileSize = 40;
        public GameMap(string path)
        {
            string[] lines = File.ReadAllLines(path);
            int rows = lines.Length;
            int cols = lines[0].Split(' ', StringSplitOptions.RemoveEmptyEntries).Length;

            mat = new TileType[rows, cols];

            for (int i = 0; i < rows; i++)
            {
                string[] vals = lines[i].Split(' ', StringSplitOptions.RemoveEmptyEntries);

                for (int j = 0; j < cols; j++)
                {
                    mat[i, j] = (TileType)byte.Parse(vals[j]);
                }
            }
        }

        public bool isSolid(int row, int col)
        {
            if (col < 0 || col >= width || row < 0 || row >= height)
            {
                return true;
            }

            TileType type = mat[row, col];

            return type == TileType.Wall || type == TileType.SteelWall;
        }

        public (int, int) GetSpawnPoint(int id)
        {
            TileType target = TileType.Player4Spawn;
            switch (id)
            {
                case 0: target = TileType.Player1Spawn; break;
                case 1: target = TileType.Player2Spawn; break;
                case 2: target = TileType.Player3Spawn; break;
                case 3: target = TileType.Player4Spawn; break;
            }

            for (int i = 0; i < height; i++)
            {
                for (int j = 0; j < width; j++)
                {
                    if (mat[i, j] == target)
                    {
                        return (j * TileSize, i * TileSize);
                    }
                }
            }

            return (400, 400);
        }


    }
    internal class MapManager { }
}
