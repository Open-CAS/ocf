/*
 * Copyright(c) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "utils_rbtree.h"

void ocf_rb_tree_init(struct ocf_rb_tree *tree, ocf_rb_tree_node_cmp_cb cmp)
{
	tree->root = NULL;
	tree->cmp = cmp;
}

static void ocf_rb_tree_update_parent(struct ocf_rb_tree *tree,
		struct ocf_rb_node *node, struct ocf_rb_node *old_node,
		struct ocf_rb_node *new_node)
{
	if (!node->parent)
		tree->root = new_node;
	else if (old_node == node->parent->left)
		node->parent->left = new_node;
	else if (old_node == node->parent->right)
		node->parent->right = new_node;
}

static void ocf_rb_tree_update_children(struct ocf_rb_node *node)
{
	if (node->left)
		node->left->parent = node;

	if (node->right)
		node->right->parent = node;
}

static void ocf_rb_tree_rotate_left(struct ocf_rb_tree *tree,
		struct ocf_rb_node *node)
{
	struct ocf_rb_node *right = node->right;

	node->right = right->left;

	if (node->right)
		node->right->parent = node;

	right->parent = node->parent;

	ocf_rb_tree_update_parent(tree, node, node, right);

	right->left = node;
	node->parent = right;
}

static void ocf_rb_tree_rotate_right(struct ocf_rb_tree *tree,
		struct ocf_rb_node *node)
{
	struct ocf_rb_node *left = node->left;

	node->left = left->right;

	if (node->left)
		node->left->parent = node;

	left->parent = node->parent;

	ocf_rb_tree_update_parent(tree, node, node, left);

	left->right = node;
	node->parent = left;
}

static void ocf_rb_tree_fix_violation(struct ocf_rb_tree *tree,
		struct ocf_rb_node *node)
{
	struct ocf_rb_node *parent, *grandparent, *uncle;
	int tmp;

	while (node->red && node->parent && node->parent->red) {
		parent = node->parent;
		grandparent = parent->parent;

		if (!grandparent)
			break;

		if (parent == grandparent->left) {
			/* Parent is left child */
			uncle = grandparent->right;

			if (uncle && uncle->red) {
				/* Uncle is red -> recolor */
				grandparent->red = true;
				parent->red = false;
				uncle->red = false;
				node = grandparent; /* Recheck grandparent */
			} else if (node == parent->right) {
				/* Node is right child -> rot left */
				ocf_rb_tree_rotate_left(tree, parent);
				node = parent;
				parent = node->parent;
			} else {
				/* Node is left child -> rot right + recolor */
				ocf_rb_tree_rotate_right(tree, grandparent);
				tmp = parent->red;
				parent->red = grandparent->red;
				grandparent->red = tmp;
				node = parent;
			}
		} else {
			/* Parent is right child */
			uncle = grandparent->left;

			if (uncle && uncle->red) {
				/* Uncle is red -> recolor */
				grandparent->red = true;
				parent->red = false;
				uncle->red = false;
				node = grandparent; /* Recheck grandparent */
			} else if (node == parent->left) {
				/* Node is left child -> rot right */
				ocf_rb_tree_rotate_right(tree, parent);
				node = parent;
				parent = node->parent;
			} else {
				/* Node is left child -> rot left + recolor */
				ocf_rb_tree_rotate_left(tree, grandparent);
				tmp = parent->red;
				parent->red = grandparent->red;
				grandparent->red = tmp;
				node = parent;
			}
		}
	}

	/* Final recolor */
	tree->root->red = false;
}

void ocf_rb_tree_insert(struct ocf_rb_tree *tree, struct ocf_rb_node *node)
{
	struct ocf_rb_node *iter, *new_iter;
	int cmp;

	node->left = NULL;
	node->right = NULL;

	if (!tree->root) {
		node->red = false;
		node->parent = NULL;
		tree->root = node;
		return;
	}

	for (new_iter = tree->root; new_iter;) {
		iter = new_iter;
		cmp = tree->cmp(node, iter);
		new_iter = (cmp < 0) ? iter->left : iter->right;
	}

	node->red = true;
	node->parent = iter;
	if (cmp < 0)
		iter->left = node;
	else
		iter->right = node;

	ocf_rb_tree_fix_violation(tree, node);
}

static void ocf_rb_tree_swap(struct ocf_rb_tree *tree,
		struct ocf_rb_node *node1, struct ocf_rb_node *node2)
{
	struct ocf_rb_node tmp;

	if (node1->left == node2)
		node1->left = node1;
	else if (node1->right == node2)
		node1->right = node1;
	else if (node1->parent == node2)
		node1->parent = node1;

	if (node2->left == node1)
		node2->left = node2;
	else if (node2->right == node1)
		node2->right = node2;
	else if (node2->parent == node1)
		node2->parent = node2;

	tmp = *node1;
	*node1 = *node2;
	*node2 = tmp;

	ocf_rb_tree_update_parent(tree, node1, node2, node1);
	ocf_rb_tree_update_parent(tree, node2, node1, node2);

	ocf_rb_tree_update_children(node1);
	ocf_rb_tree_update_children(node2);
}

static struct ocf_rb_node *ocf_rb_tree_successor(struct ocf_rb_node *node)
{
	struct ocf_rb_node *succ;

	if (!node->right)
		return NULL;

	for (succ = node->right; succ->left;)
		succ = succ->left;

	return succ;
}

static struct ocf_rb_node *ocf_rb_tree_predecessor(struct ocf_rb_node *node)
{
	struct ocf_rb_node *pred;

	if (!node->left)
		return NULL;

	for (pred = node->left; pred->right;)
		pred = pred->right;

	return pred;
}

static struct ocf_rb_node *ocf_rb_tree_bst_replacement(struct ocf_rb_node *node)
{
	if (node->left && node->right)
		return ocf_rb_tree_successor(node);

	if (node->left)
		return node->left;

	if (node->right)
		return node->right;

	return NULL;
}

static struct ocf_rb_node *ocf_rb_tree_sibling(struct ocf_rb_node *node)
{
	if (!node->parent)
		return NULL;

	return (node == node->parent->left) ?
			node->parent->right : node->parent->left;
}


void ocf_rb_tree_fix_double_black(struct ocf_rb_tree *tree,
		struct ocf_rb_node *node)
{
	struct ocf_rb_node *sibling;

	while (true) {
		if (!node->parent) {
			/* Reached root -> end */
			break;
		}

		sibling = ocf_rb_tree_sibling(node);

		if (!sibling) {
			/* No sibling -> move up */
			node = node->parent;
			continue;
		}

		if (sibling->red) {
			/* Sibling is red -> recolor, rot and repeat */
			node->parent->red = true;
			sibling->red = false;
			if (sibling == node->parent->left)
				ocf_rb_tree_rotate_right(tree, node->parent);
			else
				ocf_rb_tree_rotate_left(tree, node->parent);
			continue;
		}

		if (sibling->left && sibling->left->red) {
			/* Sibling has left red child -> recolor and rot */
			if (sibling == node->parent->left) {
				sibling->left->red = sibling->red;
				sibling->red = node->parent->red;
				ocf_rb_tree_rotate_right(tree, node->parent);
			} else {
				sibling->left->red = node->parent->red;
				ocf_rb_tree_rotate_right(tree, sibling);
				ocf_rb_tree_rotate_left(tree, node->parent);
			}
			node->parent->red = false;
			break;
		} else if (sibling->right && sibling->right->red) {
			/* Sibling has right red child -> recolor and rot */
			if (sibling == node->parent->left) {
				sibling->right->red = node->parent->red;
				ocf_rb_tree_rotate_left(tree, sibling);
				ocf_rb_tree_rotate_right(tree, node->parent);
			} else {
				sibling->right->red = sibling->red;
				sibling->red = node->parent->red;
				ocf_rb_tree_rotate_left(tree, node->parent);
			}
			node->parent->red = false;
			break;
		} else {
			/* Sibling has both black children */
			sibling->red = true;
			if (!node->parent->red) {
				/* Parent is black -> move up */
				node = node->parent;
				continue;
			}
			/* Parent is red -> recolor */
			node->parent->red = false;
			break;
		}
	}
}

void ocf_rb_tree_remove(struct ocf_rb_tree *tree, struct ocf_rb_node *node)
{
	struct ocf_rb_node *sibling, *rep;

	while (true) {
		sibling = ocf_rb_tree_sibling(node);
		rep = ocf_rb_tree_bst_replacement(node);

		if (!rep) {
			/* Node has no children -> remove */
			if (node == tree->root) {
				tree->root = NULL;
			} else {
				if (!node->red)
					ocf_rb_tree_fix_double_black(tree, node);
				else if (sibling)
					sibling->red = true;

				ocf_rb_tree_update_parent(tree, node, node, NULL);
			}
			break;
		}

		if (!rep->left & !rep->right) {
			/* BST replacement is leaf -> swap and remove */
			ocf_rb_tree_swap(tree, node, rep);

			if (!node->red)
				ocf_rb_tree_fix_double_black(tree, node);

			ocf_rb_tree_update_parent(tree, node, node, NULL);
			break;
		}

		/* BST replacement has children -> swap and repeat */
		ocf_rb_tree_swap(tree, node, rep);
	}
}

bool ocf_rb_tree_can_update(struct ocf_rb_tree *tree,
                struct ocf_rb_node *node, struct ocf_rb_node *new_node)
{
        struct ocf_rb_node *iter = tree->root;
        int cmp = 0;

        while (iter) {
                if (iter == node)
                        break;

                cmp = tree->cmp(new_node, iter);
                iter = (cmp < 0) ? iter->left : iter->right;
        }

        if (!iter)
                return false;

        cmp = tree->cmp(new_node, iter);

        if (cmp < 0) {
                iter = ocf_rb_tree_predecessor(iter);
                if (!iter)
                        return true;
                cmp = tree->cmp(new_node, iter);
                return (cmp > 0);
        }

        if (cmp > 0) {
                iter = ocf_rb_tree_successor(iter);
                if (!iter)
                        return true;
                cmp = tree->cmp(new_node, iter);
                return (cmp < 0);
        }

        return true;
}

struct ocf_rb_node *ocf_rb_tree_find(struct ocf_rb_tree *tree,
		struct ocf_rb_node *node)
{
	struct ocf_rb_node *iter = tree->root;
	int cmp = 0;

	while (iter) {
		cmp = tree->cmp(node, iter);
		if (!cmp)
			break;

		iter = (cmp < 0) ? iter->left : iter->right;
	}

	return iter;
}
