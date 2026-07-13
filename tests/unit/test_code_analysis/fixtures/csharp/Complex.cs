using System;

namespace ComplexApp
{
    public class badlyNamedService
    {
        public int processData(int[] items, int threshold, bool flag)
        {
            var result = 0;
            if (items != null)
            {
                for (var i = 0; i < items.Length; i++)
                {
                    if (items[i] > threshold)
                    {
                        for (var j = 0; j < items[i]; j++)
                        {
                            if (flag)
                            {
                                try
                                {
                                    result += j;
                                }
                                catch
                                {
                                }
                            }
                        }
                    }
                }
            }
            return result;
        }

        public void doWork(string input)
        {
            try
            {
                Console.WriteLine(input);
            }
            catch
            {
            }
        }
    }
}
