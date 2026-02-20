fn main(matrix: [[Field; 3]; 2], row: u32, col: u32, expected: pub Field) {
    assert(row < 2);
    assert(col < 3);

    let value = matrix[row][col];
    assert(value == expected);
}
